package main

import (
	"encoding/json"

	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v4/go/aws/ec2"
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

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
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

		pDbAccessCidr := "0.0.0.0/0"

		//@fixme - replace these fields with secret inputs
		pDbMasterUsername := "tempuser"
		pDbMasterUserPassword := "Temp-master-password-vnoxzghoahrtwfnoaovnasf12!"

		// @todo - can these be converted into a struct?
		pTagEnvironment := "dev"
		pTagProjectCostCenter := "dev"
		pTagConfidentiality := "none"
		pTagCompliance := "none"

		// "ID of the security group (e.g., sg-0234se). One will be created for you if left empty."
		// var pCustomSecurityGroupId *string = nil

		pPubliclyAccessible := true

		pMaxConcurrentCluster := "1"

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

		redshiftClusterParameterGroup, redshiftClusterParameterGroupErr := redshift.NewParameterGroup(ctx, "cluster-paramter-group", &redshift.ParameterGroupArgs{
			Description: pulumi.String("Redshift-Cluster-Parameter-Group-" + pGeneratedUniqueId),
			Family:      pulumi.String("redshift-1.0"),
			Parameters: redshift.ParameterGroupParameterArray{
				redshift.ParameterGroupParameterArgs{
					Name:  pulumi.String("enable_user_activity_logging"),
					Value: pulumi.String("false"),
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

		// glueCatalogDb, glueCatalogDbErr := glue.NewCatalogDatabase(ctx, "glue-catalog", &glue.CatalogDatabaseArgs{
		// 	CatalogId: ctx.,
		// 	TargetDatabase: glue.CatalogDatabaseTargetDatabaseArgs{
		// 		CatalogId: pulumi.String("temp"),
		// 		DatabaseName: ,
		// 	}
		// })

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
							StorageClass: pulumi.String("Glacier"),
							Days:         pulumi.Int(14),
						},
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

		if redshiftLoggingBucketErr != nil {
			return redshiftLoggingBucketErr
		}

		bucketPolicyString := redshiftLoggingS3Bucket.Arn.ApplyT(func(_args interface{}) (string, error) {
			bucketArn := _args.(string)

			jsonBucketPolicy, jsonBucketPolicyErr := json.Marshal(
				(map[string]interface{}{
					"Version": "2012-10-17",
					"Id":      "MYBUCKETPOLICY",
					"Statement": []map[string]interface{}{
						{
							"Sid":    "IPAllow",
							"Effect": "Allow",
							"Principal": map[string]interface{}{
								"AWS": "arn:aws:iam::" + redshiftLoggingAccountRegionIdMap("us-east-1") + ":user/logs",
							},
							"Action":   "s3:GetBucketAcl",
							"Resource": bucketArn,
						},
						{
							"Sid":    "IPAllow",
							"Effect": "Allow",
							"Principal": map[string]interface{}{
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
			return redshiftLoggingS3BucketPolicyErr
		}

		pRedshiftSingleNodeClusterCondition := "single-node" // or multi-node

		pNodeType := "dc2.large"
		pMaintenanceWindow := "sat:05:00-sat:05:30"

		redshiftCluster, redshiftClusterErr := redshift.NewCluster(ctx, "redshift-cluster", &redshift.ClusterArgs{
			ClusterType:       pulumi.String(pRedshiftSingleNodeClusterCondition),
			ClusterIdentifier: pulumi.String(pDatabaseName + pGeneratedUniqueId),
			// NumberOfNodes: ,
			NodeType:     pulumi.String(pNodeType),
			DatabaseName: pulumi.String(pDatabaseName),
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
			Logging: redshift.ClusterLoggingArgs{
				BucketName: redshiftLoggingS3Bucket.ID(),
				// @fixme - make this a parameter
				Enable:      pulumi.Bool(true),
				S3KeyPrefix: pulumi.String("AWSLogs"),
			},

			// @fixme - remove this line, or add it only for dev environment
			SkipFinalSnapshot: pulumi.Bool(true),
			// IamRoles

			Tags: pulumi.StringMap{
				"Name":              pulumi.String("Redshift Cluster"),
				"Environment":       pulumi.String(pTagEnvironment),
				"ProjectCostCenter": pulumi.String(pTagProjectCostCenter),
				"Confidentiality":   pulumi.String(pTagConfidentiality),
				"Compliance":        pulumi.String(pTagCompliance),
			},
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

		// ctx.Export("StackName", pulumi.String("@todo"))
		ctx.Export("RedshiftClusterEndpoint", redshiftCluster.Endpoint)
		ctx.Export("RedshiftPort", redshiftCluster.Port)
		ctx.Export("RedshiftCluster", redshiftCluster.ID())
		ctx.Export("RedshiftParameterGroupName", redshiftClusterParameterGroup.Name)
		ctx.Export("RedshiftDatabaseName", redshiftCluster.DatabaseName)
		ctx.Export("RedshiftUsername", pulumi.String(pDbMasterUsername))
		// ctx.Export("RedshiftClusterIAMRole", pulumi.String("@todo"))
		// ctx.Export("GlueCatalogDbName", pulumi.String("@todo"))
		// ctx.Export("PSQLCommand", pulumi.String("@todo"))

		return nil
	})
}
