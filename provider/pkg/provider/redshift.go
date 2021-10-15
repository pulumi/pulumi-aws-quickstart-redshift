// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	"encoding/json"
	"fmt"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/cloudwatch"

	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/glue"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/redshift"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type ClusterArgs struct {
	DbPort                      int                     `pulumi:"dbPort"`
	MaxConcurrentCluster        string                  `pulumi:"maxConcurrentCluster"`
	EnableLogging               *bool                   `pulumi:"enableLogging"`
	GlueCatalogDatabaseName     string                  `pulumi:"glueCatalogDatabaseName"`
	RedshiftLoggingS3BucketName string                  `pulumi:"redshiftLoggingS3BucketName"`
	NumDbNodes                  int                     `pulumi:"numDbNodes"`
	DbNodeType                  string                  `pulumi:"dbNodeType"`
	DbName                      string                  `pulumi:"dbName"`
	DbMasterUsername            string                  `pulumi:"dbMasterUsername"`
	DbMasterPassword            pulumi.StringInput      `pulumi:"dbMasterPassword"`
	DbMaintenanceWindow         string                  `pulumi:"dbMaintenanceWindow"`
	PubliclyAccessible          *bool                   `pulumi:"publiclyAccessible"`
	NotificationEmail           string                  `pulumi:"notificationEmail"`
	VpcID                       pulumi.StringInput      `pulumi:"vpcID"`
	SubnetIDs                   pulumi.StringArrayInput `pulumi:"subnetIDs"`
	AdditionalSecurityGroupIDs  pulumi.StringArrayInput `pulumi:"additionalSecurityGroupIDs"`
	EnableEventSubscription     *bool                   `pulumi:"enableEventSubscription"`
	DbClusterIdentifier         string                  `pulumi:"dbClusterIdentifier"`
}

type Cluster struct {
	pulumi.ResourceState
}

func NewCluster(ctx *pulumi.Context,
	name string, args *ClusterArgs, opts ...pulumi.ResourceOption) (*Cluster, error) {
	if args == nil {
		args = &ClusterArgs{}
	}

	component := &Cluster{}
	err := ctx.RegisterComponentResource("aws-quickstart-redshift:index:Cluster", name, component, opts...)
	if err != nil {
		return nil, err
	}

	current, err := aws.GetCallerIdentity(ctx, nil, nil)
	if err != nil {
		return nil, err
	}

	enableUserActivityLogging := "false"
	enableLogging := false
	if args.EnableLogging != nil && *args.EnableLogging {
		enableUserActivityLogging = "true"
		enableLogging = *args.EnableLogging
	}

	maxConcurrentCluster := "1"
	if args.MaxConcurrentCluster != "" {
		maxConcurrentCluster = args.MaxConcurrentCluster
	}

	enableEventSubscription := true
	if args.EnableEventSubscription != nil {
		enableEventSubscription = *args.EnableEventSubscription
	}

	redshiftClusterParameterGroup, redshiftClusterParameterGroupErr := redshift.NewParameterGroup(ctx, fmt.Sprintf("%s-cluster-paramter-group", name), &redshift.ParameterGroupArgs{
		Description: pulumi.String(fmt.Sprintf("Redshift-Cluster-Parameter-Group-%s", name)),
		Family:      pulumi.String("redshift-1.0"),
		Parameters: redshift.ParameterGroupParameterArray{
			redshift.ParameterGroupParameterArgs{
				Name:  pulumi.String("enable_user_activity_logging"),
				Value: pulumi.String(enableUserActivityLogging),
			},
			redshift.ParameterGroupParameterArgs{
				Name:  pulumi.String("require_ssl"),
				Value: pulumi.String("true"),
			},
			redshift.ParameterGroupParameterArgs{
				Name:  pulumi.String("auto_analyze"),
				Value: pulumi.String("true"),
			},
			redshift.ParameterGroupParameterArgs{
				Name:  pulumi.String("statement_timeout"),
				Value: pulumi.String("43200000"),
			},
			redshift.ParameterGroupParameterArgs{
				Name:  pulumi.String("max_concurrency_scaling_clusters"),
				Value: pulumi.String(maxConcurrentCluster),
			},
		},
	}, pulumi.Parent(component))
	if redshiftClusterParameterGroupErr != nil {
		return nil, redshiftClusterParameterGroupErr
	}

	redshiftClusterSubnetGroup, redshiftClusterSubnetGroupErr := redshift.NewSubnetGroup(ctx, fmt.Sprintf("%s-redshift-cluster-subnet-group", name), &redshift.SubnetGroupArgs{
		Description: pulumi.String(fmt.Sprintf("Cluster subnet group %s", name)),
		SubnetIds:   args.SubnetIDs,
	}, pulumi.Parent(component))
	if redshiftClusterSubnetGroupErr != nil {
		return nil, redshiftClusterSubnetGroupErr
	}

	if args.GlueCatalogDatabaseName != "" {
		_, catalogDatabaseErr := glue.NewCatalogDatabase(ctx, "glue-catalog", &glue.CatalogDatabaseArgs{
			CatalogId: pulumi.String(current.AccountId),
			TargetDatabase: glue.CatalogDatabaseTargetDatabaseArgs{
				CatalogId:    pulumi.String(current.AccountId),
				DatabaseName: pulumi.String(args.GlueCatalogDatabaseName),
			},
		}, pulumi.Parent(component))
		if nil != catalogDatabaseErr {
			return nil, catalogDatabaseErr
		}
	}

	var redshiftLoggingInput *redshift.ClusterLoggingArgs
	var redshiftIamRolesInput pulumi.StringArray
	if enableLogging {
		redshiftLoggingS3Bucket, redshiftLoggingBucketErr := s3.NewBucket(ctx, fmt.Sprintf("%s-redshift-logging-bucket", name), &s3.BucketArgs{
			LifecycleRules: s3.BucketLifecycleRuleArray{
				s3.BucketLifecycleRuleArgs{
					Id: pulumi.String("RedshiftLogsArchivingToGlacier"),
					Expiration: s3.BucketLifecycleRuleExpirationArgs{
						Days: pulumi.Int(30),
					},
					Enabled: pulumi.Bool(false),
					Transitions: s3.BucketLifecycleRuleTransitionArray{
						s3.BucketLifecycleRuleTransitionArgs{
							StorageClass: pulumi.String("GLACIER"),
							Days:         pulumi.Int(14),
						},
					},
				},
			},
		}, pulumi.Parent(component))
		if redshiftLoggingBucketErr != nil {
			return nil, redshiftLoggingBucketErr
		}

		bucketPolicyString := redshiftLoggingS3Bucket.Arn.ApplyT(func(_args interface{}) (string, error) {
			bucketArn := _args.(string)

			jsonBucketPolicy, jsonBucketPolicyErr := json.Marshal(
				map[string]interface{}{
					"Version": "2012-10-17",
					"Id":      "RedshiftLoggingS3BucketPolicy",
					"Statement": []map[string]interface{}{
						{
							"Sid":    "GetBucketAcl",
							"Effect": "Allow",
							"Principal": map[string]interface{}{
								"AWS": "arn:aws:iam::" + redshiftLoggingAccountRegionIdMap("us-east-1") + ":user/logs",
							},
							"Action":   "s3:GetBucketAcl",
							"Resource": bucketArn,
						},
						{
							"Sid":    "PutLogs",
							"Effect": "Allow",
							"Principal": map[string]interface{}{
								"AWS": "arn:aws:iam::" + redshiftLoggingAccountRegionIdMap("us-east-1") + ":user/logs",
							},
							"Action":   "s3:PutObject",
							"Resource": bucketArn + "/AWSLogs/*",
						},
					},
				},
			)

			return string(jsonBucketPolicy), jsonBucketPolicyErr
		})

		_, redshiftLoggingS3BucketPolicyErr := s3.NewBucketPolicy(ctx, fmt.Sprintf("%s-logging-bucket-policy", name), &s3.BucketPolicyArgs{
			Bucket: redshiftLoggingS3Bucket.ID(),
			Policy: bucketPolicyString,
		}, pulumi.Parent(component))
		if redshiftLoggingS3BucketPolicyErr != nil {
			return nil, redshiftLoggingS3BucketPolicyErr
		}

		redshiftLoggingInput = &redshift.ClusterLoggingArgs{
			BucketName:  redshiftLoggingS3Bucket.ID(),
			Enable:      pulumi.Bool(*args.EnableLogging),
			S3KeyPrefix: pulumi.String("AWSLogs"),
		}
	}

	if enableLogging && args.RedshiftLoggingS3BucketName != "" {
		iamRolePolicy, err := json.Marshal(
			map[string]interface{}{
				"Version": "2012-10-17",
				"Id":      "",
				"Statement": []map[string]interface{}{
					{
						"Effect":   "Allow",
						"Sid":      "",
						"Resource": "*",
						"Action": []string{
							"glue:CreateDatabase",
							"glue:DeleteDatabase",
							"glue:GetDatabase",
							"glue:GetDatabases",
							"glue:UpdateDatabase",
							"glue:CreateTable",
							"glue:DeleteTable",
							"glue:BatchDeleteTable",
							"glue:UpdateTable",
							"glue:GetTable",
							"glue:GetTables",
							"glue:BatchCreatePartition",
							"glue:CreatePartition",
							"glue:DeletePartition",
							"glue:BatchDeletePartition",
							"glue:UpdatePartition",
							"glue:GetPartition",
							"glue:GetPartitions",
							"glue:BatchGetPartition",
							"logs:*",
						},
					},
					{
						"Effect": "Allow",
						"Action": []string{
							"glue:CreateDatabase",
							"glue:DeleteDatabase",
							"s3:GetBucketLocation",
							"s3:GetObject",
							"s3:ListMultipartUploadParts",
							"s3:ListBucket",
							"s3:ListBucketMultipartUploads",
						},
						"Resource": []string{
							fmt.Sprintf("arn:aws:s3:::%s", args.RedshiftLoggingS3BucketName),
							fmt.Sprintf("arn:aws:s3:::%s/*", args.RedshiftLoggingS3BucketName),
						},
					},
				},
			},
		)
		if err != nil {
			return nil, err
		}

		assumeRolePolicyString, assumeRolePolicyStringErr := json.Marshal(
			map[string]interface{}{
				"Version": "2012-10-17",
				"Statement": []map[string]interface{}{
					{
						"Action": "sts:AssumeRole",
						"Effect": "Allow",
						"Sid":    "",
						"Principal": map[string]interface{}{
							"Service": []string{
								"redshift.amazonaws.com",
								"glue.amazonaws.com",
							},
						},
					},
				},
			},
		)
		if assumeRolePolicyStringErr != nil {
			return nil, assumeRolePolicyStringErr
		}

		redshiftIamRole, redshiftIamRoleErr := iam.NewRole(ctx, fmt.Sprintf("%s-redshift-iam-role", name), &iam.RoleArgs{
			Path:             pulumi.String('/'),
			AssumeRolePolicy: pulumi.String(assumeRolePolicyString),
			InlinePolicies: iam.RoleInlinePolicyArray{
				iam.RoleInlinePolicyArgs{
					Name:   pulumi.String("redshift-access"),
					Policy: pulumi.String(iamRolePolicy),
				},
			},
		}, pulumi.Parent(component))
		if redshiftIamRoleErr != nil {
			return nil, redshiftIamRoleErr
		}

		redshiftIamRolesInput = append(redshiftIamRolesInput, redshiftIamRole.ID())
	}

	numDbNodes := 2
	if args.NumDbNodes > 0 {
		numDbNodes = args.NumDbNodes
	}
	clusterType := "single-node"
	if numDbNodes > 1 {
		clusterType = "multi-node"
	}

	dbPort := 8200
	if args.DbPort != 0 {
		dbPort = args.DbPort
	}

	dbMaintenanceWindow := "sat:05:00-sat:05:30"
	if args.DbMaintenanceWindow != "" {
		dbMaintenanceWindow = args.DbMaintenanceWindow
	}

	publiclyAccessible := false
	if args.PubliclyAccessible != nil {
		publiclyAccessible = *args.PubliclyAccessible
	}

	clusterArgs := &redshift.ClusterArgs{
		ClusterType:       pulumi.String(clusterType),
		ClusterIdentifier: pulumi.String(args.DbClusterIdentifier),
		NumberOfNodes:     pulumi.Int(numDbNodes),
		NodeType:          pulumi.String(args.DbNodeType),
		DatabaseName:      pulumi.String(args.DbName),

		Port:                             pulumi.Int(dbPort),
		MasterUsername:                   pulumi.String(args.DbMasterUsername),
		MasterPassword:                   args.DbMasterPassword,
		ClusterParameterGroupName:        redshiftClusterParameterGroup.Name,
		PreferredMaintenanceWindow:       pulumi.String(dbMaintenanceWindow),
		AutomatedSnapshotRetentionPeriod: pulumi.Int(8),
		PubliclyAccessible:               pulumi.Bool(publiclyAccessible),
		ClusterSubnetGroupName:           redshiftClusterSubnetGroup.Name,

		Logging: redshiftLoggingInput,

		SkipFinalSnapshot: pulumi.Bool(true),
		IamRoles:          redshiftIamRolesInput,
	}
	if args.AdditionalSecurityGroupIDs != nil {
		clusterArgs.VpcSecurityGroupIds = args.AdditionalSecurityGroupIDs
	}

	redshiftCluster, redshiftClusterErr := redshift.NewCluster(ctx, fmt.Sprintf("%s-redshift-cluster", name),
		clusterArgs, pulumi.Parent(component))
	if redshiftClusterErr != nil {
		return nil, redshiftClusterErr
	}

	if enableEventSubscription {
		snsTopic, snsTopicErr := sns.NewTopic(ctx, fmt.Sprintf("%s-sns", name), nil, pulumi.Parent(component))
		if snsTopicErr != nil {
			return nil, snsTopicErr
		}

		snsTopicSubscription, snsTopicSubscriptionErr := sns.NewTopicSubscription(ctx, fmt.Sprintf("%s-sns-topic-subscription", name), &sns.TopicSubscriptionArgs{
			Topic:    snsTopic,
			Protocol: pulumi.String("email"),
			Endpoint: pulumi.String(args.NotificationEmail),
		}, pulumi.Parent(component))
		if snsTopicSubscriptionErr != nil {
			return nil, snsTopicSubscriptionErr
		}

		_, diskSpaceUsedAlarmErr := cloudwatch.NewMetricAlarm(ctx, fmt.Sprintf("%s-disk-space-used-alarm", name), &cloudwatch.MetricAlarmArgs{
			ActionsEnabled:   pulumi.Bool(true),
			AlarmActions:     pulumi.Array{snsTopicSubscription.ID()},
			AlarmDescription: pulumi.String("PercentageDiskSpaceUsed"),
			Dimensions: pulumi.StringMap{
				"ClusterIdentifier": redshiftCluster.ID(),
			},
			MetricName:         pulumi.String("CPUUtilization"),
			Statistic:          pulumi.String("Average"),
			Namespace:          pulumi.String("AWS/Redshift"),
			Threshold:          pulumi.Float64Ptr(65),
			Unit:               pulumi.String("Percent"),
			ComparisonOperator: pulumi.String("GreaterThanThreshold"),
			Period:             pulumi.Int(300),
			EvaluationPeriods:  pulumi.Int(3),
		}, pulumi.Parent(component))
		if diskSpaceUsedAlarmErr != nil {
			return nil, diskSpaceUsedAlarmErr
		}

		_, highCpuUtilizationAlarmErr := cloudwatch.NewMetricAlarm(ctx, fmt.Sprintf("%s-high-cpu-utilization-alarm", name), &cloudwatch.MetricAlarmArgs{
			ActionsEnabled:   pulumi.Bool(true),
			AlarmActions:     pulumi.Array{snsTopicSubscription.ID()},
			AlarmDescription: pulumi.String("PercentageDiskSpaceUsed"),
			Dimensions: pulumi.StringMap{
				"ClusterIdentifier": redshiftCluster.ID(),
			},
			MetricName:         pulumi.String("High-CPUUtilization"),
			Statistic:          pulumi.String("Average"),
			Namespace:          pulumi.String("AWS/Redshift"),
			Threshold:          pulumi.Float64Ptr(95),
			Unit:               pulumi.String("Percent"),
			ComparisonOperator: pulumi.String("GreaterThanThreshold"),
			Period:             pulumi.Int(300),
			EvaluationPeriods:  pulumi.Int(3),
		}, pulumi.Parent(component))
		if highCpuUtilizationAlarmErr != nil {
			return nil, highCpuUtilizationAlarmErr
		}
	}

	if err := ctx.RegisterResourceOutputs(component, pulumi.Map{}); err != nil {
		return nil, err
	}

	return component, nil
}

func redshiftLoggingAccountRegionIdMap(regionId string) string {
	switch regionId {
	case "us-east-1":
		return "193672423079"
	case "us-east-2":
		return "391106570357"
	case "us-west-1":
		return "262260360010"
	case "us-west-2":
		return "902366379725"
	case "ap-east-1":
		return "313564881002"
	case "ap-south-1":
		return "865932855811"
	case "ap-northeast-3":
		return "090321488786"
	case "ap-northeast-2":
		return "760740231472"
	case "ap-southeast-1":
		return "361669875840"
	case "ap-southeast-2":
		return "762762565011"
	case "ap-northeast-1":
		return "404641285394"
	case "ca-central-1":
		return "907379612154"
	case "cn-north-1":
		return "111890595117"
	case "cn-northwest-1":
		return "660998842044"
	case "eu-west-1":
		return "210876761215"
	case "eu-central-1":
		return "053454850223"
	case "eu-west-2":
		return "307160386991"
	case "eu-west-3":
		return "915173422425"
	case "eu-north-1":
		return "729911121831"
	case "sa-east-1":
		return "075028567923"
	default:
		return ""
	}
}
