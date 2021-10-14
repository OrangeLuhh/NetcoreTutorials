using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthenticatinDynamicValidation.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace AuthenticatinDynamicValidation.PolicyProvider
{
    public class DynamicPolicyAuthorizationFactory
    {
        public static AuthorizationPolicy Create(string policyName)
        {
            var parts = policyName.Split(".");
            var type = parts.First();
            var value = parts.Last();

            switch(type)
            {
                case DynamicPolicies.Rank:
                    return new AuthorizationPolicyBuilder()
                        .RequireClaim("Rank", value)
                        .Build();
                case DynamicPolicies.Level:
                    return new AuthorizationPolicyBuilder()
                        .AddRequirements(new PermitAuthorizationRequirement(Convert.ToInt32(value)))
                        .Build();
                default:
                    return null;
            }
        }
    }

    public static class DynamicPolicies
    {
        public const string Level = "Level";
        public const string Rank = "Rank";

        public static IEnumerable<string> Get()
        {
            yield return Level;
            yield return Rank;
        }
    }

    public class AuthorizationPolicyProvider
        : DefaultAuthorizationPolicyProvider
    {
        public AuthorizationPolicyProvider(IOptions<AuthorizationOptions> options) : base(options)
        {
        }

        public override Task<AuthorizationPolicy> GetPolicyAsync(string policyName)
        {
            foreach(var policy in DynamicPolicies.Get())
            {
                if(policyName.StartsWith(policy))
                {
                    var policyInstance = DynamicPolicyAuthorizationFactory.Create(policyName);

                    return Task.FromResult(policyInstance);
                }
            }

            return base.GetPolicyAsync(policyName);
        }
    }

    public class PermitAuthorizationRequirement : IAuthorizationRequirement
    {
        public int Level {get;}

        public PermitAuthorizationRequirement(int level)
        {
            Level = level;
        }
    }

    public class PermitAuthorizationHadnlerWithData
        : AuthorizationHandler<PermitAuthorizationRequirement, CookieJar>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermitAuthorizationRequirement requirement, CookieJar resource)
        {
            throw new NotImplementedException();
        }
    }

    public class PermitAuthorizationHadnler
        : AuthorizationHandler<PermitAuthorizationRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, 
            PermitAuthorizationRequirement requirement)
        {
            var claimValue = Convert.ToInt32(context.User.Claims.FirstOrDefault(o => o.Type == DynamicPolicies.Level)?.Value ?? "0");

            if(requirement.Level <= claimValue)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }

    public class PermitAuthAttribute : AuthorizeAttribute
    {
        public PermitAuthAttribute(int level)
        {
            Policy = $"{DynamicPolicies.Level}.{level}";
        }
    }
}
