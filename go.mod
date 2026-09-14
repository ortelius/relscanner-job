module relscanner

go 1.27.1

require (
	github.com/anchore/syft v1.51.1
	github.com/arangodb/go-driver/v2 v2.4.0
	github.com/glebarez/go-sqlite v1.23.0
	github.com/go-enry/go-enry/v2 v2.9.6
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-containerregistry v0.22.1
	github.com/google/go-github/v91 v91.0.0
	github.com/ortelius/ortelius/v12 v12.0.529
	github.com/spf13/cobra v1.10.2
	golang.org/x/oauth2 v0.36.0
	helm.sh/helm/v4 v4.3.0
)

// Pinned to match helm.sh/helm/v4 v4.2.4's own go.mod exactly. Helm's SDK
// is not independently version-compatible with arbitrary k8s.io/* releases
// -- without these pins, `go mod tidy` has no other constraint on these
// modules anywhere in this graph and will select @latest, which can pull in
// a k8s.io/apimachinery built against a different major version of
// sigs.k8s.io/structured-merge-diff than the rest of the resolved k8s.io/*
// family expects, breaking compilation. Bump these only in lockstep with
// the helm.sh/helm/v4 version above.
require (
	cel.dev/expr v0.25.2 // indirect
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.23.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.13.0 // indirect
	cloud.google.com/go/monitoring v1.30.0 // indirect
	cloud.google.com/go/storage v1.64.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/CycloneDX/cyclonedx-go v0.11.0 // indirect
	github.com/DataDog/zstd v1.5.7 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.35.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.59.0 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.59.0 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/Masterminds/squirrel v1.5.4 // indirect
	github.com/Microsoft/go-winio v0.6.3-0.20251027160822-ad3df93bed29 // indirect
	github.com/Microsoft/hcsshim v0.15.0-rc.3 // indirect
	github.com/OneOfOne/xxhash v1.2.8 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/STARRY-S/zip v0.2.3 // indirect
	github.com/acobaugh/osrelease v0.1.0 // indirect
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/agext/levenshtein v1.2.3 // indirect
	github.com/anchore/clio v0.1.1 // indirect
	github.com/anchore/fangs v0.1.1 // indirect
	github.com/anchore/go-collections v0.1.1 // indirect
	github.com/anchore/go-homedir v0.1.1 // indirect
	github.com/anchore/go-logger v0.1.1 // indirect
	github.com/anchore/go-lzo v0.1.1 // indirect
	github.com/anchore/go-macholibre v0.1.1 // indirect
	github.com/anchore/go-rpmdb v0.2.0 // indirect
	github.com/anchore/go-struct-converter v0.2.1 // indirect
	github.com/anchore/go-sync v0.1.1 // indirect
	github.com/anchore/go-version v1.2.2-0.20200701162849-18adb9c92b9b // indirect
	github.com/anchore/packageurl-go v0.2.0 // indirect
	github.com/anchore/stereoscope v0.3.0 // indirect
	github.com/andybalholm/brotli v1.2.2 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/apparentlymart/go-textseg/v17 v17.0.1 // indirect
	github.com/aquasecurity/go-npm-version v0.0.2 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.1 // indirect
	github.com/aquasecurity/go-version v0.0.1 // indirect
	github.com/arangodb/go-velocypack v0.0.0-20200318135517-5af53c29c67e // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go-v2 v1.43.5 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.17 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.36 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.35 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.36 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.29 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.36 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.37 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.107.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.5 // indirect
	github.com/aws/smithy-go v1.27.7 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/becheran/wildmatch-go v1.0.0 // indirect
	github.com/bgentry/go-netrc v0.0.0-20140422174119-9fd32a8b3d3d // indirect
	github.com/bitnami/go-version v0.0.0-20260728133343-2aa268af0217 // indirect
	github.com/blakesmith/ar v0.0.0-20190502131153-809d4375e1fb // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/bmatcuk/doublestar/v4 v4.10.0 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.5 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/cayleygraph/quad v1.3.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chai2010/gettext-go v1.0.2 // indirect
	github.com/charmbracelet/colorprofile v0.4.3 // indirect
	github.com/charmbracelet/lipgloss v1.1.0 // indirect
	github.com/charmbracelet/x/ansi v0.11.8 // indirect
	github.com/charmbracelet/x/cellbuf v0.0.15 // indirect
	github.com/charmbracelet/x/term v0.2.2 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/containerd/cgroups/v3 v3.1.3 // indirect
	github.com/containerd/containerd/api v1.11.1 // indirect
	github.com/containerd/containerd/v2 v2.3.3 // indirect
	github.com/containerd/continuity v0.5.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v1.0.0-rc.4 // indirect
	github.com/containerd/plugin v1.1.0 // indirect
	github.com/containerd/ttrpc v1.2.9 // indirect
	github.com/containerd/typeurl/v2 v2.3.0 // indirect
	github.com/cyphar/filepath-securejoin v0.7.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/deitch/magic v0.0.0-20240306090643-c67ab88f10cb // indirect
	github.com/diskfs/go-diskfs v1.9.4 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/cli v29.7.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.9.8 // indirect
	github.com/docker/go-connections v0.8.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/dylibso/observe-sdk/go v0.0.0-20240819160327-2d926c5d788a // indirect
	github.com/elliotchance/phpserialize v1.4.0 // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/envoyproxy/go-control-plane/envoy v1.37.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/evanphx/json-patch/v5 v5.9.11 // indirect
	github.com/exponent-io/jsonpath v0.0.0-20210407135951-1de76d718b3f // indirect
	github.com/extism/go-sdk v1.7.1 // indirect
	github.com/facebookincubator/nvdtools v0.1.5 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/felixge/fgprof v0.9.5 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/fluxcd/cli-utils v1.2.1 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.15 // indirect
	github.com/github/go-spdx/v2 v2.7.0 // indirect
	github.com/go-enry/go-oniguruma v1.2.1 // indirect
	github.com/go-errors/errors v1.5.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.1 // indirect
	github.com/go-git/go-git/v5 v5.19.2 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v0.21.1 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.1 // indirect
	github.com/go-restruct/restruct v1.2.0-alpha // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gofrs/flock v0.13.0 // indirect
	github.com/gohugoio/hashstructure v1.0.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/licensecheck v0.3.1 // indirect
	github.com/google/osv-scanner v1.9.2 // indirect
	github.com/google/pprof v0.0.0-20260802141513-ef3492d7dac3 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.21 // indirect
	github.com/googleapis/gax-go/v2 v2.23.0 // indirect
	github.com/gookit/color v1.6.1 // indirect
	github.com/gosuri/uitable v0.0.4 // indirect
	github.com/gpustack/gguf-parser-go v0.25.0 // indirect
	github.com/hashicorp/aws-sdk-go-base/v2 v2.0.0-beta.74 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-getter v1.8.7 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hashicorp/hcl/v2 v2.24.0 // indirect
	github.com/henvic/httpretty v0.2.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/ianlancetaylor/demangle v0.0.0-20250417193237-f615e6bd150b // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jinzhu/copier v0.4.0 // indirect
	github.com/jmoiron/sqlx v1.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kastenhq/goversion v0.0.0-20230811215019-93b2f8823953 // indirect
	github.com/kevinburke/ssh_config v1.6.0 // indirect
	github.com/kkdai/maglev v0.2.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/lib/pq v1.12.3 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/lucasb-eyer/go-colorful v1.4.1 // indirect
	github.com/mailru/easyjson v0.9.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-runewidth v0.0.27 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mholt/archives v0.1.5 // indirect
	github.com/mikelolasagasti/xz v1.0.1 // indirect
	github.com/minio/minlz v1.2.0 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/moby/api v1.55.0 // indirect
	github.com/moby/moby/client v0.5.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/sequential v0.7.0 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.1 // indirect
	github.com/moby/sys/userns v0.2.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/muesli/termenv v0.16.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/nix-community/go-nix v0.0.0-20250101154619-4bdde671e0a1 // indirect
	github.com/nwaples/rardecode/v2 v2.3.0 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.3.0 // indirect
	github.com/olekukonko/ll v0.1.8 // indirect
	github.com/olekukonko/tablewriter v1.1.4 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.3.0 // indirect
	github.com/package-url/packageurl-go v0.1.6 // indirect
	github.com/pandatix/go-cvss v0.6.2 // indirect
	github.com/pborman/indent v1.2.1 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.28 // indirect
	github.com/piprate/json-gold v0.8.0 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pkg/profile v1.7.0 // indirect
	github.com/pkg/xattr v0.4.12 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/rubenv/sql-migrate v1.8.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/rust-secure-code/go-rustaudit v0.0.0-20250226111315-e20ec32e963c // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/sassoftware/go-rpmutils v0.4.0 // indirect
	github.com/scylladb/go-set v1.0.3-0.20200225121959-cc7b2070d91e // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/skeema/knownhosts v1.3.2 // indirect
	github.com/smallnest/ringbuffer v0.1.1 // indirect
	github.com/sorairolake/lzip-go v0.3.8 // indirect
	github.com/spdx/gordf v0.0.0-20250128162952-000978ccd6fb // indirect
	github.com/spdx/tools-golang v0.6.0-rc4 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/spiffe/go-spiffe/v2 v2.8.1 // indirect
	github.com/stangelandcl/ppmd v0.1.1 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/sylabs/sif/v2 v2.24.1 // indirect
	github.com/sylabs/squashfs v1.0.6 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tetratelabs/wabin v0.0.0-20230304001439-f6f874872834 // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	github.com/therootcompany/xz v1.0.1 // indirect
	github.com/ulikunitz/xz v0.5.16 // indirect
	github.com/vbatts/go-mtree v0.7.0 // indirect
	github.com/vifraa/gopom v1.0.0 // indirect
	github.com/wagoodman/go-partybus v0.0.0-20230516145632-8ccac152c651 // indirect
	github.com/wagoodman/go-progress v0.0.0-20260303201901-10176f79b2c0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/xo/terminfo v1.0.0 // indirect
	github.com/zclconf/go-cty v1.19.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/detectors/gcp v1.45.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.70.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.70.0 // indirect
	go.opentelemetry.io/otel v1.45.0 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/trace v1.45.0 // indirect
	go.opentelemetry.io/proto/otlp v1.10.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org v0.0.0-20260112195520-a5071408f32f // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/exp v0.0.0-20260811152304-ee035b5b010f // indirect
	golang.org/x/mod v0.39.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/api v0.293.0 // indirect
	google.golang.org/genproto v0.0.0-20260810153831-ec0a7760b754 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260810153831-ec0a7760b754 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260810153831-ec0a7760b754 // indirect
	google.golang.org/grpc v1.83.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	howett.net/plist v1.0.1 // indirect
	k8s.io/api v0.36.1 // indirect
	k8s.io/apiextensions-apiserver v0.36.1 // indirect
	k8s.io/apimachinery v0.36.1 // indirect
	k8s.io/apiserver v0.36.1 // indirect
	k8s.io/cli-runtime v0.36.1 // indirect
	k8s.io/client-go v0.36.1 // indirect
	k8s.io/component-base v0.36.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260319004828-5883c5ee87b9 // indirect
	k8s.io/kubectl v0.36.1 // indirect
	k8s.io/utils v0.0.0-20260319190234-28399d86e0b5 // indirect
	modernc.org/libc v1.75.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.0 // indirect
	modernc.org/sqlite v1.56.0 // indirect
	oras.land/oras-go/v2 v2.6.1 // indirect
	sigs.k8s.io/controller-runtime v0.24.1 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/kustomize/api v0.21.1 // indirect
	sigs.k8s.io/kustomize/kyaml v0.21.1 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.2 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

// Plain `require` above is only a floor under Go's MVS -- something else in
// the build graph (transitively, possibly several hops deep) can want a
// different k8s.io/apimachinery than v0.36.1, and MVS always selects the
// maximum version requested by anything in the graph. That skew is exactly
// what produces errors like "sigs.k8s.io/structured-merge-diff/vN ... as
// ... vM" -- two incompatible major versions of the same module pulled in
// by two different resolved k8s.io/* versions. `replace` is unconditional
// and wins regardless of what else asks for a newer version, so it's the
// only reliable way to force the whole k8s.io/* + sigs.k8s.io/* family to
// the single consistent set helm.sh/helm/v4 v4.2.4 was actually built
// against. Unlike the v3 SDK, v4 moved from docker/docker-based oras-go v1
// to oras.land/oras-go/v2, so no docker/docker replace is needed here.
replace (
	k8s.io/api => k8s.io/api v0.37.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.37.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.37.0
	k8s.io/apiserver => k8s.io/apiserver v0.37.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.37.0
	k8s.io/client-go => k8s.io/client-go v0.37.0
	k8s.io/component-base => k8s.io/component-base v0.37.0
	k8s.io/klog/v2 => k8s.io/klog/v2 v2.140.0
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20260911184034-7970a1e230da
	k8s.io/kubectl => k8s.io/kubectl v0.37.0
	k8s.io/utils => k8s.io/utils v0.0.0-20260707023825-cf1189d6abe3
	sigs.k8s.io/json => sigs.k8s.io/json v0.0.0-20260909141634-11ed52e25bc5
	sigs.k8s.io/kustomize/api => sigs.k8s.io/kustomize/api v0.21.1
	sigs.k8s.io/kustomize/kyaml => sigs.k8s.io/kustomize/kyaml v0.21.1
	sigs.k8s.io/structured-merge-diff/v7 => sigs.k8s.io/structured-merge-diff/v6 v7.0.0
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.6.0
)
