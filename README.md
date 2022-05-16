# Pulumi AWS Aurora Redshift

Easily deploy an Amaon Redshift data warehouse for big data analytics, with accompanying features like alarms, logging, encryption, and multi-AZ redundancy. This component is based on the best practices recommended by AWS in the [Modular architecture for Amazon Redshift](https://aws.amazon.com/quickstart/architecture/amazon-redshift/)

# Examples

See the `/examples` directory for more

Go:
```go
_, err = quickstartRedshift.NewCluster(ctx, "example-redshift-cluster", &quickstartRedshift.ClusterArgs{
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
```

Typescript
```typescript
const cluster = new redshift.Cluster("example-redshift-cluster", {
  vpcID: multiAvailabilityZoneVpc.vpcID,
  subnetIDs: subnetIDs,
  dbPort: 5432,
  dbClusterIdentifier: "example-redshift-cluster",  
  dbMasterUsername: "mainuser",
  notificationEmail: databaseNotificationEmail,
  enableEventSubscription: true,
  dbMasterPassword: dbPasswordSecret,
  dbName: "main",
  dbNodeType: "dc2.large"
})

```
