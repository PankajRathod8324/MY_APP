using System.Diagnostics;
using System.Security.Claims;
using DAL.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace PizzaShop.Controllers;


public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;

    public HomeController(ILogger<HomeController> logger)
    {
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

    // [Authorize(Policy = "ChefOnly")]
    // [Authorize(Roles = "Chef")]
    public IActionResult Dashboard()
    {
        var userClaims = User.Claims;

        // Log all claims for debugging
        foreach (var claim in userClaims)
        {
            _logger.LogInformation($"Claim Type: {claim.Type}, Claim Value: {claim.Value}");
        }

        var roles = userClaims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value).ToList();

        // Log roles for debugging
        if (roles.Any())
        {
            _logger.LogInformation($"Roles: {string.Join(", ", roles)}");
        }
        else
        {
            _logger.LogInformation("No roles found in user claims.");
        }

        return View();
    }


    [Authorize(Policy = "Admin")]
    public IActionResult Userpage()
    {
        return View();
    }

    public IActionResult Profile()
    {
        return View();
    }

    public IActionResult Changepassword()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}



//   [HttpGet("ResetPassword")]
//         public async Task<IActionResult> Resetpasswordpage(string email, string token)
//         {
// var user = await _userService.GetUserByEmailAsync(email);
// Console.WriteLine("uSER'S eMAIL"+user.Email);
// Console.WriteLine(token);
// if (user == null)
// {
//     return NotFound();
// }

// var model = new ResetPasswordVM
// {
//     Email = user.Email,
//     Token = token
// };

//             return View(model);
//         }