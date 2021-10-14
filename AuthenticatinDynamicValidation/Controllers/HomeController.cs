using System;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using AuthenticatinDynamicValidation.PolicyProvider;

namespace AuthenticatinDynamicValidation.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly IAuthorizationService _authorizationService;

        public HomeController(IAuthorizationService authorizationService)
        {
            this._authorizationService = authorizationService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Secret()
        {
            return View();
        }

        [PermitAuth(3)]
        public IActionResult Permit1()
        {
            return View(nameof(Secret));
        }

        [PermitAuth(8)]
        public IActionResult Permit8()
        {
            return View(nameof(Secret));
        }

        [AllowAnonymous]
        public IActionResult Authenticate()
        {
            var userClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim(ClaimTypes.Email, "Bob@email.com"),
                new Claim(DynamicPolicies.Level, "6")
            };
            var userIdentity = new ClaimsIdentity(userClaims, "UserCard");

            var driverClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, "Bob"),
                new Claim("DrivingLicense", "A+")
            };
            var licenseIdentity = new ClaimsIdentity(driverClaims, "License Identity");

            var userPrincipal = new ClaimsPrincipal(new[] { userIdentity, licenseIdentity });

            HttpContext.SignInAsync(userPrincipal);

            return RedirectToAction(nameof(Index));
        }
    }
}
