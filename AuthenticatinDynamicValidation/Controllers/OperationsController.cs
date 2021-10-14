using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticatinDynamicValidation.Controllers
{
    public class OperationsController : Controller
    {
        private readonly IAuthorizationService _authorizationService;

        public OperationsController(IAuthorizationService authorizationService)
        {
            this._authorizationService = authorizationService;
        }

        public async Task<IActionResult> Open()
        {
            // from database
            var cookieJar = new CookieJar();

            await _authorizationService.AuthorizeAsync(User, cookieJar, CookieJarAuthOperations.Open);

            return View();
        }
    }

    public class CookieJarAuthorizationHadnler 
        : AuthorizationHandler<OperationAuthorizationRequirement, CookieJar>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, 
            OperationAuthorizationRequirement requirement,
            CookieJar cookieJar)
        {
            if(requirement.Name == CookieJarOperations.Open)
            {
                if(context.User.Identity.IsAuthenticated)
                {
                    context.Succeed(requirement);
                }
            }
            else if (requirement.Name.Equals(CookieJarOperations.Look))
            {
                if(context.User.HasClaim("Friend", "Good"))
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }
    }

    public static class CookieJarAuthOperations
    {
        public static OperationAuthorizationRequirement Open = new OperationAuthorizationRequirement()
        {
            Name = "Open"
        };

        public static OperationAuthorizationRequirement Look = new OperationAuthorizationRequirement()
        {
            Name = "Look"
        };
    }

    public static class CookieJarOperations
    {
        public static string Open = "Open";

        public static string Look = "Look";
    }

    public class CookieJar
    {
        public string Name { get; set; }
    }
}
