// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Azure.Core;
using System;
using System.Dynamic;
using System.Globalization;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Azure.Identity
{
    /// <summary>
    /// Enables authentication to Azure Active Directory using an Azure Access Token,
    /// details configured in the following environment variables:
    /// <list type="table">
    /// <listheader><term>Variable</term><description>Description</description></listheader>
    /// <item><term>AZURE_ACCESS_TOKEN</term><description>The access token for the account.</description></item>
    /// <item><term>AZURE_ACCESS_TOKEN_EXPIRESON</term><description>The access token expiration for the account.</description></item>
    /// </list>
    /// This credential is useful for local container development and testing scenarios, where the user in control of the container
    /// has an account in Azure and the container does not have a way of authenticating because providing credentials would require
    /// secrets to be saved in the source control.  Before the container image is launched, the Azure CLI command, az account get-access-token,
    /// is invoked to set a container environment variable.  PowerShell example:
    /// $Env:AZURE_ACCESS_TOKEN=(az account get-access-token | ConvertFrom-Json).accessToken
    /// $Env:AZURE_ACCESS_TOKEN_EXPIRESON=(az account get-access-token | ConvertFrom-Json).expiresOn
    /// </summary>
    public class AccessTokenCredential : TokenCredential
    {
        private const string UnavailableErrorMessage = "AccessTokenCredential authentication unavailable. Environment variables are not fully configured.";
        private readonly CredentialPipeline _pipeline;
        private AccessToken _token;

        /// <summary>
        /// Creates an instance of the EnvironmentCredential class and reads client secret details from environment variables.
        /// If the expected environment variables are not found at this time, the GetToken method will return the default <see cref="AccessToken"/> when invoked.
        /// </summary>
        public AccessTokenCredential()
            : this(CredentialPipeline.GetInstance(null))
        { }

        internal AccessTokenCredential(CredentialPipeline pipeline)
        {
            _pipeline = pipeline;

            string accessToken = EnvironmentVariables.AccessToken;
            DateTimeOffset accessTokenExpiresOn = DateTimeOffset.Parse(EnvironmentVariables.AccessTokenExpiresOn, new DateTimeFormatInfo());

            if (!string.IsNullOrEmpty(accessToken))
            {
                //if the token is JSON
                if (accessToken.Trim().StartsWith("{", StringComparison.InvariantCulture))
                {
                    dynamic json = JsonSerializer.Deserialize<ExpandoObject>(accessToken);

                    try
                    {
                        _token = new AccessToken(json.accessToken, DateTimeOffset.Parse(json.expiresOn));
                    }
                    catch
                    {}
                }
                else
                {
                    _token = new AccessToken(accessToken.Trim(), accessTokenExpiresOn);
                }
            }
        }

        /// <summary>
        /// Obtains a token from the Azure Active Directory service, using the specified client details specified in the environment variables
        /// AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET or AZURE_USERNAME and AZURE_PASSWORD to authenticate.
        /// This method is called automatically by Azure SDK client libraries. You may call this method directly, but you must also handle token caching and token refreshing.
        /// </summary>
        /// <remarks>
        /// If the environment variables AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are not specified, the default <see cref="AccessToken"/>
        /// </remarks>
        /// <param name="requestContext">The details of the authentication request.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> controlling the request lifetime.</param>
        /// <returns>An <see cref="AccessToken"/> which can be used to authenticate service client calls.</returns>
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken = default)
        {
            return GetTokenImpl(requestContext);
        }

        /// <summary>
        /// Obtains a token from the Azure Active Directory service, using the specified client details specified in the environment variables
        /// AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET or AZURE_USERNAME and AZURE_PASSWORD to authenticate.
        /// This method is called automatically by Azure SDK client libraries. You may call this method directly, but you must also handle token caching and token refreshing.
        /// </summary>
        /// <remarks>
        /// If the environment variables AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are not specifeid, the default <see cref="AccessToken"/>
        /// </remarks>
        /// <param name="requestContext">The details of the authentication request.</param>
        /// <param name="cancellationToken">A <see cref="CancellationToken"/> controlling the request lifetime.</param>
        /// <returns>An <see cref="AccessToken"/> which can be used to authenticate service client calls, or a default <see cref="AccessToken"/>.</returns>
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            return new ValueTask<AccessToken>(GetTokenImpl(requestContext));
        }

        private AccessToken GetTokenImpl(TokenRequestContext requestContext)
        {
            using CredentialDiagnosticScope scope = _pipeline.StartGetTokenScope("AccessTokenCredential.GetToken", requestContext);

            if (string.IsNullOrEmpty(_token.Token))
            {
                throw scope.FailWrapAndThrow(new CredentialUnavailableException(UnavailableErrorMessage));
            }

            return scope.Succeeded(_token);
        }
    }
}
