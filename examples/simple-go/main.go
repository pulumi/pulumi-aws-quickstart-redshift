package main

import (
	quickstartRedshift "github.com/pulumi/pulumi-aws-quickstart-redshift/sdk/go/aws"
	quickstartVpc "github.com/pulumi/pulumi-aws-quickstart-vpc/sdk/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi/config"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		publicSubnet1Cidr := "10.0.128.0/20"
		privateSubnet1ACidr := "10.0.32.0/19"
		publicSubnet2Cidr := "10.0.64.0/19"

		databaseNotificationEmail := "aidan@hool.co"
		enableEventSubscription := true

		vpc, err := quickstartVpc.NewVpc(ctx, "simple-vpc", &quickstartVpc.VpcArgs{
			CidrBlock: "10.0.0.0/16",
			AvailabilityZoneConfig: []quickstartVpc.AvailabilityZoneArgs{
				quickstartVpc.AvailabilityZoneArgs{
					AvailabilityZone:   "us-east-1a",
					PublicSubnetCidr:   &publicSubnet1Cidr,
					PrivateSubnetACidr: &privateSubnet1ACidr,
				},
				quickstartVpc.AvailabilityZoneArgs{
					AvailabilityZone: "us-east-1b",
					PublicSubnetCidr: &publicSubnet2Cidr,
				},
			},
		})

		if err != nil {
			return err
		}

		dbPort := 5432

		cfg := config.New(ctx, "")

		_, err = quickstartRedshift.NewCluster(ctx, "smiple-redshift", &quickstartRedshift.ClusterArgs{
			VpcID:                   vpc.VpcID,
			SubnetIDs:               vpc.PrivateSubnetIDs,
			DbPort:                  &dbPort,
			DbClusterIdentifier:     "example-redshift-cluster",
			DbMasterUsername:        "mainuser",
			NotificationEmail:       &databaseNotificationEmail,
			EnableEventSubscription: &enableEventSubscription,
			DbMasterPassword:        cfg.RequireSecret("dbPassword"),
			DbName:                  "main",
			DbNodeType:              "dc2.large",
		})

		if err != nil {
			return err
		}

		return nil
	})
}
