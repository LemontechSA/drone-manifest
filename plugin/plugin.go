// Copyright (c) 2023, the Drone Plugins project authors.
// Please see the AUTHORS file for details. All rights reserved.
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file.

package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/LemontechSA/drone-manifest-ecr/tagging"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"

	"github.com/drone/drone-go/drone"
	"github.com/drone/drone-template-lib/template"
	"github.com/estesp/manifest-tool/v2/pkg/registry"
	"github.com/estesp/manifest-tool/v2/pkg/types"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v3"
)

// Args provides plugin execution arguments.
type (
	Args struct {
		Pipeline

		// Level defines the plugin log level.
		Level string `envconfig:"PLUGIN_LOG_LEVEL"`

		// Skip verification of certificates
		SkipVerify bool `envconfig:"PLUGIN_SKIP_VERIFY"`

		// Lint plugin
		Lint bool `envconfig:"PLUGIN_LINT" default:"true"`

		// Plugin specific
		AccessKeyID     string   `envconfig:"PLUGIN_ACCESS_KEY_ID"`
		SecretAccessKey string   `envconfig:"PLUGIN_SECRET_ACCESS_KEY"`
		Region          string   `envconfig:"PLUGIN_REGION"`
		AssumeRole      string   `envconfig:"PLUGIN_ASSUME_ROLE"`
		ExternalID      string   `envconfig:"PLUGIN_EXTERNAL_ID"`
		Password        string   `envconfig:"PLUGIN_PASSWORD"`
		Platforms       []string `envconfig:"PLUGIN_PLATFORMS"`
		Target          string   `envconfig:"PLUGIN_TARGET"`
		Template        string   `envconfig:"PLUGIN_TEMPLATE"`
		Spec            string   `envconfig:"PLUGIN_SPEC"`
		IgnoreMissing   bool     `envconfig:"PLUGIN_IGNORE_MISSING"`
		Tags            []string `envconfig:"PLUGIN_TAGS"`
		AutoTag         bool     `envconfig:"PLUGIN_AUTO_TAG"`
	}
)

var errConfiguration = errors.New("configuration error")
var defaultRegion = "us-east-1"

// Exec executes the plugin.
func Exec(ctx context.Context, args *Args) error {
	linter := ""

	if args.Lint {
		issues, warnings := lintArgs(args)
		linter = fmt.Sprintf("lint: %d issue(s) found\n%s", issues, warnings)
		logrus.Info(linter)
	}

	err := verifyArgs(args)
	if err != nil {
		return fmt.Errorf("error in the configuration: %w", err)
	}

	// Auto tag behavior
	if args.AutoTag {
		if tagging.UseDefaultTag(args.Commit.Ref, args.Repo.Branch) {
			args.Tags = tagging.DefaultTags(args.Commit.Ref)
		} else {
			logrus.Infof("skipping automated tags for %s", args.Commit.Ref)
			return nil
		}
	}

	// Get the yaml to push
	var yamlFunc func(*Args) (types.YAMLInput, error)
	if args.Spec != "" {
		yamlFunc = yamlFromSpec
	} else {
		yamlFunc = yamlFromArgs
	}

	yamlInput, err := yamlFunc(args)
	if err != nil {
		return fmt.Errorf("could not create manifest spec: %w", err)
	}

	region := args.Region
	assumeRole := args.AssumeRole
	externalId := args.ExternalID

	if region == "" {
		region = defaultRegion
	}

	if args.AccessKeyID != "" && args.SecretAccessKey != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", args.AccessKeyID)
		os.Setenv("AWS_SECRET_ACCESS_KEY", args.SecretAccessKey)
	}

	sess, err := session.NewSession(&aws.Config{Region: &region})
	if err != nil {
		log.Fatalf("error creating aws session: %v", err)
	}

	svc := getECRClient(sess, assumeRole, externalId)
	username, password, _, err := getAuthInfo(svc)

	if err != nil {
		log.Fatalf("error getting ECR auth: %v", err)
	}

	logrus.Info("pushing manifest")

	digest, length, err := registry.PushManifestList(
		username,           // --access-key-id
		password,           // --secret-access-key
		yamlInput,          // --from-spec
		args.IgnoreMissing, // --ignore-missing
		args.SkipVerify,    // --insecure
		false,              // --plain-http
		types.Docker,       // --type
		"",                 // --docker-cfg
	)
	if err != nil {
		return fmt.Errorf("could not push manifest list: %w", err)
	}

	logrus.Infof("manifest pushed: digest %s %d", digest, length)

	// Create the card data
	cardData := struct {
		Image  string `json:"image"`
		Digest string `json:"digest"`
		Linter string `json:"linter"`
	}{
		Image:  yamlInput.Image,
		Digest: digest,
		Linter: linter,
	}

	data, _ := json.Marshal(cardData)
	card := drone.CardInput{
		Schema: "https://drone-plugins.github.io/drone-manifest/card.json",
		Data:   data,
	}
	writeCard(args.Card.Path, &card)

	return nil
}

func getECRClient(sess *session.Session, role string, externalId string) *ecr.ECR {
	if role == "" {
		return ecr.New(sess)
	}
	if externalId != "" {
		return ecr.New(sess, &aws.Config{
			Credentials: stscreds.NewCredentials(sess, role, func(p *stscreds.AssumeRoleProvider) {
				p.ExternalID = &externalId
			}),
		})
	} else {
		return ecr.New(sess, &aws.Config{
			Credentials: stscreds.NewCredentials(sess, role),
		})
	}
}

func getAuthInfo(svc *ecr.ECR) (username, password, registry string, err error) {
	var result *ecr.GetAuthorizationTokenOutput
	var decoded []byte

	result, err = svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return
	}

	auth := result.AuthorizationData[0]
	token := *auth.AuthorizationToken
	decoded, err = base64.StdEncoding.DecodeString(token)
	if err != nil {
		return
	}

	registry = strings.TrimPrefix(*auth.ProxyEndpoint, "https://")
	creds := strings.Split(string(decoded), ":")
	username = creds[0]
	password = creds[1]
	return
}

func lintArgs(args *Args) (issues int, warnings string) {
	issues = 0
	var warningsBuilder strings.Builder

	if value, present := os.LookupEnv("PLUGIN_INSECURE"); present {
		warningsBuilder.WriteString("remove insecure from config and use skip_verify instead")
		args.SkipVerify = value == "true"
		issues++
	}

	return issues, warningsBuilder.String()
}

func verifyArgs(args *Args) error {
	if args.Spec == "" {
		if len(args.Platforms) == 0 {
			return fmt.Errorf("no platforms provided: %w", errConfiguration)
		}

		if args.Target == "" {
			return fmt.Errorf("no target provided: %w", errConfiguration)
		}

		if args.Template == "" {
			return fmt.Errorf("no template provided: %w", errConfiguration)
		}
	} else if len(args.Platforms) != 0 || args.Target != "" || args.Template != "" {
		return fmt.Errorf("both spec and arguments provided: %w", errConfiguration)
	}

	return nil
}

func yamlFromSpec(args *Args) (types.YAMLInput, error) {
	var yamlInput types.YAMLInput
	var raw []byte

	// if spec is not a valid file, assume inlining
	if _, err := os.Stat(args.Spec); os.IsNotExist(err) {
		raw = []byte(args.Spec)
	} else { // otherwise read it
		raw, err = os.ReadFile(args.Spec)

		if err != nil {
			return yamlInput, fmt.Errorf("failed to read template: %w", errConfiguration)
		}
	}

	// Render using the old plugin format
	p := toLegacyPlugin(args)
	yamlFile, err := template.RenderTrim(string(raw), p)
	if err != nil {
		return yamlInput, fmt.Errorf("can't render template: %w", err)
	}

	// Modified from https://github.com/estesp/manifest-tool/blob/main/v2/cmd/manifest-tool/push.go
	err = yaml.Unmarshal([]byte(yamlFile), &yamlInput)
	if err != nil {
		return yamlInput, fmt.Errorf("can't unmarshal to yaml: %w", err)
	}

	return yamlInput, nil
}

func yamlFromArgs(args *Args) (types.YAMLInput, error) {
	// Modified from https://github.com/estesp/manifest-tool/blob/main/v2/cmd/manifest-tool/push.go
	srcImages := []types.ManifestEntry{}

	for _, platform := range args.Platforms {
		osArchArr := strings.Split(platform, "/")
		if len(osArchArr) != 2 && len(osArchArr) != 3 {
			return types.YAMLInput{}, fmt.Errorf("platforms must be a string slice where one value is of the form 'os/arch': %w", errConfiguration)
		}
		variant := ""
		os, arch := osArchArr[0], osArchArr[1]
		if len(osArchArr) == 3 {
			variant = osArchArr[2]
		}
		srcImages = append(srcImages, types.ManifestEntry{
			Image: strings.Replace(strings.Replace(strings.Replace(args.Template, "ARCH", arch, 1), "OS", os, 1), "VARIANT", variant, 1),
			Platform: ocispec.Platform{
				OS:           os,
				Architecture: arch,
				Variant:      variant,
			},
		})
	}

	return types.YAMLInput{
		Image:     args.Target,
		Tags:      args.Tags,
		Manifests: srcImages,
	}, nil
}
