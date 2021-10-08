package main

import (
	"encoding/json"
	"strconv"

	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ec2"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/glue"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/redshift"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/s3"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/sns"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func redshiftLoggingAccountRegionIdMap(regionId string) string {
	switch regionId {
	case "us-gov-west-1":
		return "xx"
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
	}

	return "xx"
}

type Tags struct {
	Environment       string
	ProjectCostCenter string
	Confidentiality   string
	Compliance        string
}

/*******************************
 * REDSHIFT LOGGING ACCESS
 *******************************/
/**
 * Create a bucket for redshift to write logs to.
 */
func createLoggingBucket(ctx *pulumi.Context, tags Tags) (*s3.Bucket, error) {

	redshiftLoggingS3Bucket, redshiftLoggingBucketErr := s3.NewBucket(ctx, "redshift-logging-bucket", &s3.BucketArgs{
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
		Tags: pulumi.StringMap{
			"Name":              pulumi.String("allow_db_access"),
			"Environment":       pulumi.String(tags.Environment),
			"ProjectCostCenter": pulumi.String(tags.ProjectCostCenter),
			"Confidentiality":   pulumi.String(tags.Confidentiality),
			"Compliance":        pulumi.String(tags.Compliance),
		},
	})

	if redshiftLoggingBucketErr != nil {
		return nil, redshiftLoggingBucketErr
	}

	bucketPolicyString := redshiftLoggingS3Bucket.Arn.ApplyT(func(_args interface{}) (string, error) {
		bucketArn := _args.(string)

		jsonBucketPolicy, jsonBucketPolicyErr := json.Marshal(
			(map[string]interface{}{
				"Version": "2012-10-17",
				"Id":      "RedshiftLoggingS3BucketPolicy",
				"Statement": []map[string]interface{}{
					{
						"Sid":    "GetBucketAcl",
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							// @fixme - region
							"AWS": "arn:aws:iam::" + redshiftLoggingAccountRegionIdMap("us-east-1") + ":user/logs",
						},
						"Action":   "s3:GetBucketAcl",
						"Resource": bucketArn,
					},
					{
						"Sid":    "PutLogs",
						"Effect": "Allow",
						"Principal": map[string]interface{}{
							// @fixme - region
							"AWS": "arn:aws:iam::" + redshiftLoggingAccountRegionIdMap("us-east-1") + ":user/logs",
						},
						"Action":   "s3:PutObject",
						"Resource": bucketArn + "/AWSLogs/*",
					},
				},
			}),
		)

		return string(jsonBucketPolicy), jsonBucketPolicyErr
	})

	_, redshiftLoggingS3BucketPolicyErr := s3.NewBucketPolicy(ctx, "logging-bucket-policy", &s3.BucketPolicyArgs{
		Bucket: redshiftLoggingS3Bucket.ID(),
		Policy: bucketPolicyString,
	})

	if redshiftLoggingS3BucketPolicyErr != nil {
		return nil, redshiftLoggingS3BucketPolicyErr
	}

	return redshiftLoggingS3Bucket, nil
}

/**********************
 * END REDSHIFT LOGGING
 *********************/

/**
 * Create a role for Redshift Spectrum and Glue to access the S3 bucket provided by the input parameter.
 */
func createRedshiftSpectrumIAMRole(ctx *pulumi.Context, s3BucketForRedshiftSpectrumIamRole string) (*iam.Role, error) {

	iamRolePolicy, _ := json.Marshal(
		(map[string]interface{}{
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
						"arn:aws:s3:::" + s3BucketForRedshiftSpectrumIamRole,
						"arn:aws:s3:::" + s3BucketForRedshiftSpectrumIamRole + "/*",
					},
				},
			},
		}),
	)

	/************************************************
	 * IAM Redshift Role
	 ************************************************/

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

	redshiftIamRole, _ := iam.NewRole(ctx, "redshift-iam-role", &iam.RoleArgs{
		Path:             pulumi.String('/'),
		AssumeRolePolicy: pulumi.String(string(assumeRolePolicyString)),
		InlinePolicies: iam.RoleInlinePolicyArray{
			iam.RoleInlinePolicyArgs{
				Name:   pulumi.String("redshift-access"),
				Policy: pulumi.String(iamRolePolicy),
			},
		},
	})

	return redshiftIamRole, nil
}

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		current, _ := aws.GetCallerIdentity(ctx, nil, nil)

		// @fixme - not sure what the unique id is used for.
		pGeneratedUniqueId := "tempid"

		pNotificationList := "temp@hool.co"

		pVpcId := "vpc-0c1f4105aea0108b6"
		// pDbAvailabilityZones := []string{
		// 	"us-east-1a",
		// 	"us-east-1b",
		// }
		pDbSubnetIds := []string{
			"subnet-0d0f0bca649e2ca05",
			"subnet-0de5edd7b1c3410a3",
		}

		// "ID of the security group (e.g., sg-0234se). One will be created for you if left empty."
		// var pCustomSecurityGroupId *string = nil

		pDbPort := 5432
		pDatabaseName := "tempdbname"

		pNumberNodes := 1
		pEnableLogging := false

		pGlueCatalogDatabase := "tempGlueCatalogDatabase"

		pDbAccessCidr := "0.0.0.0/0"

		pDbMasterUsername := "tempuser"
		pDbMasterUserPassword := "Temp-master-password-vnoxzghoahrtwfnoaovnasf12!"

		// @todo - can these be converted into a struct?
		pTagEnvironment := "dev"
		pTagProjectCostCenter := "dev"
		pTagConfidentiality := "none"
		pTagCompliance := "none"
		// @todo - can the input just be this struct?
		// @todo Do Nils need to be handled gracefully?
		tags := Tags{
			Environment:       pTagEnvironment,
			ProjectCostCenter: pTagProjectCostCenter,
			Confidentiality:   pTagConfidentiality,
			Compliance:        pTagCompliance,
		}

		// "ID of the security group (e.g., sg-0234se). One will be created for you if left empty."
		// var pCustomSecurityGroupId *string = nil

		pPubliclyAccessible := true
		pMaxConcurrentCluster := "1"

		pS3BucketForRedshiftSpectrum := "example-bucket"

		pRedshiftSingleNodeClusterCondition := "single-node" // or multi-node

		pNodeType := "dc2.large"
		pMaintenanceWindow := "sat:05:00-sat:05:30"

		/**
		 * Redshift security group
		 */
		dbSecurityGroup, dbSecurityGroupErr := ec2.NewSecurityGroup(ctx, "allowTls", &ec2.SecurityGroupArgs{
			Description: pulumi.String("Allow TLS inbound traffic to database port"),
			VpcId:       pulumi.String(pVpcId),
			Ingress: ec2.SecurityGroupIngressArray{
				&ec2.SecurityGroupIngressArgs{
					Description: pulumi.String("TLS DB port for db access cidr"),
					FromPort:    pulumi.Int(pDbPort),
					ToPort:      pulumi.Int(pDbPort),
					Protocol:    pulumi.String("tcp"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String(pDbAccessCidr),
					},
				},
			},
			Tags: pulumi.StringMap{
				"Name":              pulumi.String("allow_db_access"),
				"Environment":       pulumi.String(pTagEnvironment),
				"ProjectCostCenter": pulumi.String(pTagProjectCostCenter),
				"Confidentiality":   pulumi.String(pTagConfidentiality),
				"Compliance":        pulumi.String(pTagCompliance),
			},
		})

		if dbSecurityGroupErr != nil {
			return dbSecurityGroupErr
		}

		enableUserActivityLogging := "false"
		if pEnableLogging {
			enableUserActivityLogging = "true"
		}

		redshiftClusterParameterGroup, redshiftClusterParameterGroupErr := redshift.NewParameterGroup(ctx, "cluster-paramter-group", &redshift.ParameterGroupArgs{
			Description: pulumi.String("Redshift-Cluster-Parameter-Group-" + pGeneratedUniqueId),
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
					Value: pulumi.String(pMaxConcurrentCluster),
				},
				// redshift.ParameterGroupParameterArgs{
				// 	Name:  pulumi.String("wlm_json_configuration"),
				// 	Value: pulumi.String("43200000"),
				// @fixme - !Sub '[ { "query_group" : [ ],"query_group_wild_card" : 0,"user_group" : [ ],"user_group_wild_card" : 0,"concurrency_scaling" : "${ConcurrencyScaling}","rules" : [ {  "rule_name" : "DiskSpilling",  "predicate" : [ { "metric_name" : "query_temp_blocks_to_disk", "operator" : ">", "value" : 100000  } ], "action" : "log"}, {  "rule_name" : "RowJoining",  "predicate" : [ { "metric_name" : "join_row_count", "operator" : ">", "value" : 1000000000 } ],  "action" : "log"} ],"priority" : "normal","queue_type" : "auto","auto_wlm" : true }, {"short_query_queue" : true } ]'
				// },
			},
		})

		if redshiftClusterParameterGroupErr != nil {
			return redshiftClusterParameterGroupErr
		}

		redshiftClusterSubnetGroup, redshiftClusterSubnetGroupErr := redshift.NewSubnetGroup(ctx, "redshift-cluster-subnet-group", &redshift.SubnetGroupArgs{
			Description: pulumi.String("Cluster subnet group"),
			SubnetIds:   pulumi.ToStringArray(pDbSubnetIds),
			Name:        pulumi.String("primary-redshift-subnet-group"),
			Tags: pulumi.StringMap{
				"Environment":       pulumi.String(pTagEnvironment),
				"ProjectCostCenter": pulumi.String(pTagProjectCostCenter),
				"Confidentiality":   pulumi.String(pTagConfidentiality),
				"Compliance":        pulumi.String(pTagCompliance),
			},
		})

		if redshiftClusterSubnetGroupErr != nil {
			return redshiftClusterSubnetGroupErr
		}

		catalogDatabase, catalogDatabaseErr := glue.NewCatalogDatabase(ctx, "glue-catalog", &glue.CatalogDatabaseArgs{
			CatalogId: pulumi.String(current.AccountId),
			TargetDatabase: glue.CatalogDatabaseTargetDatabaseArgs{
				CatalogId:    pulumi.String(current.AccountId),
				DatabaseName: pulumi.String(pGlueCatalogDatabase),
			},
		})

		if nil != catalogDatabaseErr {
			return catalogDatabaseErr
		}

		var redshiftLoggingS3Bucket *s3.Bucket = nil
		var redshiftLoggingS3BucketErr error
		var redshiftLoggingInput *redshift.ClusterLoggingArgs = nil

		if pEnableLogging {
			redshiftLoggingS3Bucket, redshiftLoggingS3BucketErr = createLoggingBucket(ctx, tags)

			redshiftLoggingInput = &redshift.ClusterLoggingArgs{
				BucketName:  redshiftLoggingS3Bucket.ID(),
				Enable:      pulumi.Bool(pEnableLogging),
				S3KeyPrefix: pulumi.String("AWSLogs"),
			}

			if redshiftLoggingS3BucketErr != nil {
				return redshiftLoggingS3BucketErr
			}
		}

		var redshiftIamRole *iam.Role = nil
		var redshiftIamRoleErr error
		var redshiftIamRolesInput pulumi.StringArray = nil

		// @fixme - nillable string on input?
		if pS3BucketForRedshiftSpectrum != "bypass" {
			redshiftIamRole, redshiftIamRoleErr = createRedshiftSpectrumIAMRole(ctx, pS3BucketForRedshiftSpectrum)

			if redshiftIamRoleErr != nil {
				return redshiftIamRoleErr
			}

			redshiftIamRolesInput = pulumi.StringArray{redshiftIamRole.ID()}
		}

		redshiftCluster, redshiftClusterErr := redshift.NewCluster(ctx, "redshift-cluster", &redshift.ClusterArgs{
			ClusterType:       pulumi.String(pRedshiftSingleNodeClusterCondition),
			ClusterIdentifier: pulumi.String(pDatabaseName + pGeneratedUniqueId),
			NumberOfNodes:     pulumi.Int(pNumberNodes),
			NodeType:          pulumi.String(pNodeType),
			DatabaseName:      pulumi.String(pDatabaseName),
			// kmsKeyId
			// Encrypted
			Port:                      pulumi.Int(pDbPort),
			MasterUsername:            pulumi.String(pDbMasterUsername),
			MasterPassword:            pulumi.String(pDbMasterUserPassword),
			ClusterParameterGroupName: redshiftClusterParameterGroup.Name,
			// SnapshotIdentifier:
			// OwnerAccount
			VpcSecurityGroupIds:              pulumi.StringArray{dbSecurityGroup.ID()},
			PreferredMaintenanceWindow:       pulumi.String(pMaintenanceWindow),
			AutomatedSnapshotRetentionPeriod: pulumi.Int(8),
			PubliclyAccessible:               pulumi.Bool(pPubliclyAccessible),
			ClusterSubnetGroupName:           redshiftClusterSubnetGroup.Name,

			Logging: redshiftLoggingInput,

			// @fixme - remove this line, or add it only for dev environment
			SkipFinalSnapshot: pulumi.Bool(true),
			IamRoles:          redshiftIamRolesInput,
			Tags: pulumi.StringMap{
				"Name":              pulumi.String("Redshift Cluster"),
				"Environment":       pulumi.String(pTagEnvironment),
				"ProjectCostCenter": pulumi.String(pTagProjectCostCenter),
				"Confidentiality":   pulumi.String(pTagConfidentiality),
				"Compliance":        pulumi.String(pTagCompliance),
			},
			// }, pulumi.DependsOn([]pulumi.Resource{redshiftIamRole}))
		})

		if redshiftClusterErr != nil {
			return redshiftClusterErr
		}

		snsTopic, snsTopicErr := sns.NewTopic(ctx, "sns", &sns.TopicArgs{})

		if snsTopicErr != nil {
			return snsTopicErr
		}

		snsTopicSubscription, snsTopicSubscriptionErr := sns.NewTopicSubscription(ctx, "sns-topic-subscription", &sns.TopicSubscriptionArgs{
			Topic:    snsTopic,
			Protocol: pulumi.String("email"),
			Endpoint: pulumi.String(pNotificationList),
		})

		if snsTopicSubscriptionErr != nil {
			return snsTopicSubscriptionErr
		}

		_, diskSpaceUsedAlarmErr := cloudwatch.NewMetricAlarm(ctx, "disk-space-used-alarm", &cloudwatch.MetricAlarmArgs{
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
		})

		if diskSpaceUsedAlarmErr != nil {
			return diskSpaceUsedAlarmErr
		}

		_, highCpuUtilizationAlarmErr := cloudwatch.NewMetricAlarm(ctx, "high-cpu-utilization-alarm", &cloudwatch.MetricAlarmArgs{
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
		})

		if highCpuUtilizationAlarmErr != nil {
			return highCpuUtilizationAlarmErr
		}

		psqlAccessCommand := redshiftCluster.Endpoint.ApplyT(func(_arg interface{}) string {
			address := _arg.(string)
			return "psql -h " + address + " -p " + strconv.Itoa(pDbPort) + " -U " + pDbMasterUsername + " -d " + pDatabaseName
		})

		ctx.Export("StackName", pulumi.String(ctx.Stack()))
		ctx.Export("RedshiftClusterEndpoint", redshiftCluster.Endpoint)
		ctx.Export("RedshiftPort", redshiftCluster.Port)
		ctx.Export("RedshiftCluster", redshiftCluster.ID())
		ctx.Export("RedshiftParameterGroupName", redshiftClusterParameterGroup.Name)
		ctx.Export("RedshiftDatabaseName", redshiftCluster.DatabaseName)
		ctx.Export("RedshiftUsername", pulumi.String(pDbMasterUsername))

		if nil != redshiftIamRole {
			ctx.Export("RedshiftClusterIAMRole", redshiftIamRole.Arn)
		}

		ctx.Export("GlueCatalogDbName", catalogDatabase.Arn)
		ctx.Export("PSQLCommandLine", psqlAccessCommand)

		return nil
	})
}
