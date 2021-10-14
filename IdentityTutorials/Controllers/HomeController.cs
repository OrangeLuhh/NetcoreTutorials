using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using IdentityTutorials.Models;
using IdentityTutorials.Data;
using Microsoft.AspNetCore.Identity;

namespace IdentityTutorials.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly AppDbContext _appDbContext;
        private readonly UserManager<IdentityUser> _userMananger;
        private readonly SignInManager<IdentityUser> _signInManager;

        public HomeController(ILogger<HomeController> logger,
            AppDbContext appDbContext,
            UserManager<IdentityUser> userMananger,
            SignInManager<IdentityUser> signInManager)
        {
            this._userMananger = userMananger;
            this._signInManager = signInManager;
            this._appDbContext = appDbContext;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            var user = await _userMananger.FindByNameAsync(username);
            
            if(user != null)
            {
                var signinResult = await _signInManager.PasswordSignInAsync(user, password, false, false);

                if(signinResult.Succeeded)
                {
                    return RedirectToAction(nameof(Index));
                }
            }

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(string username, string password)
        {
            var user = new IdentityUser()
            {
                UserName = username
            };

            var identityResult = await _userMananger.CreateAsync(user, password);

            if(identityResult.Succeeded)
            {
                await Login(username, password);
            }

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(Index));
        }
    }
}
