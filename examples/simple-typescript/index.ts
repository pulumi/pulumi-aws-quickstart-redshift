import * as pulumi from "@pulumi/pulumi";
import * as vpc from "@pulumi/aws-quickstart-vpc";
import * as redshift from "@pulumi/aws-quickstart-redshift";

const dbMasterPassword = "?SimpleExamplePassword12345?"
const dbPasswordSecret = pulumi.secret(dbMasterPassword);

const multiAvailabilityZoneVpc = new vpc.Vpc("example-aurora-vpc", {
    cidrBlock: "10.0.0.0/16",
    availabilityZoneConfig: [{
        availabilityZone: "us-east-1a",
        publicSubnetCidr: "10.0.128.0/20",
        privateSubnetACidr: "10.0.32.0/19",
    }, {
        availabilityZone: "us-east-1b",
        privateSubnetACidr: "10.0.64.0/19",
    }]
})

// type clean up for subnetIds. The VPC class thinks these private subnet ids might be undefined.
const subnetIDs = multiAvailabilityZoneVpc.privateSubnetIDs as pulumi.Output<string[]>

const cluster = new redshift.Cluster("example-redshift-cluster", {
  vpcID: multiAvailabilityZoneVpc.vpcID,
  dbPort: 5432,
  dbClusterIdentifier: "example-redshift-cluster",  
  dbMasterUsername: "mainuser",
  notificationEmail: "aidan@hool.co",
  enableEventSubscription: true,
  dbMasterPassword: dbPasswordSecret,
  dbName: "main",
  dbNodeType: "dc2.large",
  subnetIDs: subnetIDs
})

