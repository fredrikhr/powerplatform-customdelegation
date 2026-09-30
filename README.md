# Power Platform Custom Delegation

This repository provides functionality in Power Platform to perform operations
that delegate access from the Authorized User Identity in Dataverse to other
services.

## Background

### Delegation within Power Platform and Dataverse

In Power Platform `Delegation`, also referred to as `Impersonation`, is a
built-in feature that allows an authorized user in Dataver to assume the
identity of another user in Dataverse and perform operations on-behalf-of
that other user.  
_**Note**: Even though similar, this does **not** refer to an OAuth2
on-behalf-of sign-in flow._

In Power Platform a user is authorized to act on behalf of another user by
being assigned as security role granting the `prvActOnBehalfOfAnotherUser`
privilege.  
Among others, this privilege is included in the built-in
`System Administrator` and `Delegate` security roles.

Most commonly makers in Power Platform make use of Impersonation when
designing Power Automate Cloud Flows. Contrary to all other connections in
Flows, Dataverse connections are always embedded connections. When you use
the UI in Power Automate to change a Dataverse connection to use the
invoker's connection, the runtime still actually uses the design-time
connection, but impersonates the invoking user when using it.  
The same is true when designing legacy Workflow or Action processes and
you change the settings controlling which user the workflow is running as.

A user can observe the effects of an impersonation by looking at and
comparing the `Modified By` and `Modified By (Delegate)` columns:  
The `Modified By` will show the identity of the impersonat**ed** user,
while `Modified By (Delegate)` will show the identity of the
impersonat**ing** user.

Within the Power Platform SDK, i.e. when authoring code plugins for 
Dataverse, the effects of impersonation can be observed in the
Plugin Execution context:  
The value for `UserId` and `UserAzureActiveDirectoryObjectId` may differ 
from `AuthenticatedUserId` and `InitiatingUserAzureActiveDirectoryObjectId`
when Impersonation is performed.  
Likewise, a developer can explicitly perform impersonation in code by
using the `IOrganizationServiceFactory` to create a Dataverse client that
impersonates the specified User.

When using the Dataverse Web-API, you can perform Impersonation by adding
either the `CallerObjectId` or `MSCRMCallerID` HTTP header in your 
HTTP request. This is described in more detail on Microsoft Learn:  
[Impersonate another user by using the Web API](https://learn.microsoft.com/en-us/power-apps/developer/data-platform/webapi/impersonate-another-user-web-api)

### Delegation from Dataverse to other services

In the Power Platform SDK that developers use when authoring Dataverse 
code plugins, there is an interface `IOnBehalfOfTokenService` which is
available from the service provider passed to the plugin during execution.
However, calling the `AcquireToken` method on it causes an exception to be
thrown. Its message indicates that only plugin assemblies signed by a 
first-party (i.e. Microsoft) certificate are allowed to use this operation.

A Dataverse instance ships with a pre-installed Virtual Entity `aaduser`
which uses a Virtual Entity Provider located in an assembly that is signed
by Microsoft's code signing certificate. The behaviour of accessing the
`aaduser` entity indicates that Microsoft themselves like use the
`IOnBehalfOfTokenService` interface in their implementation to acquire an
access token on behalf of the user to return live data from Entra ID that
the user has access to.  
For example, in a Tenant where Guest users are disallowed from enumerating
Entra ID, accessing the `aaduser` as a guest correctly fails with the 
exact error message you otherwise get from the Microsoft Graph API.

If your plugin assembly is digitally signed with a certificate, and if you
assign a `managedidentity` entity to your plugin, you will get access 
to use the `IManagedIdentityService` interface from within the code of your
plugin and it will provide your code to acquire access tokens for any
service. However, all access tokens issued that way are tokens issued for
the application identity represented by the `managedidentity` record.  
**The issued access tokens have no relation to the actual calling user.**  
This is explained in greater detail on Microsoft Learn:
[Power Platform managed identity](https://learn.microsoft.com/en-us/power-platform/admin/managed-identity-overview)

## Motivation

In Power Platform and Dataverse a maker only has the ability to impersonate
a user when the operation takes place entirely within Dataverse.  
As a plugin author you furthermore have the ability to assume exactly one
other identity: the managed identity assigned to your plugin (if any).

This produces a challenge for the design of functionality for 
Power Platform which you would normally group together in a solution. 
Generally, you have two options:

1. All solutions share the same plugin implementing access token issuence 
with its single Managed Identity
2. Each solution re-implements the same plugin that provides access token
issuance, and each plugin (and therefore solution) is assigned their own
managed identity.

Both the options above are generally undiresable.  
Option 1 requires two totally different applications to use the same 
identity when accessing other services.  
Option 2 requires solution authors to duplicate the code of the plugin into
their own solution. And to actually invoke the plugin you also need to 
duplicate the same Custom API for each solution.

The easier solution to all this is usually to provide the parameters needed
to authenticate as an application in form of environment variables or to
just hard-code them into you solution components. The more clever approach 
to this is to use environment variables with the `Secret` datatype.  
However, in this approach a client secret (i.e. a long-living credential)
will be made accessible in application logic (e.g. in a Cloud Flow run).

None of the approaches above provide any meaningful way to solve how a 
component in a solution can impersonate a user and act on the user's behalf
for external services.

### Goal

This repository aims to provide a re-usable flexible solution to how
multiple different application might acquire short-lived access tokens to
any service without having to actual deal with confidential information.  
Furthermore, to provide a re-usable flexible solution for applications to
acquire access tokens on behalf of a user for any authorized service.

## Architecture

