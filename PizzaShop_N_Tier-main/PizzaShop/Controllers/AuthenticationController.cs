using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using PizzaShop.ViewModel;
using BLL.Interfaces;
using System.Net.Mail;
using System.Net;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.IdentityModel.Tokens.Jwt;
using DAL.Models;

namespace PizzaShop.Controllers
{
    public class AuthenticationController : Controller
    {
        private readonly IUserService _userService;


        public AuthenticationController(IUserService userService)
        {
            _userService = userService;
        }




        [HttpGet("Loginpage")]
        public IActionResult Loginpage()
        {
            var user = new LoginVM();
            if (Request.Cookies["Email"] != null && Request.Cookies["Password"] != null)
            {
                user.Email = Request.Cookies["Email"];
                user.Password = Request.Cookies["Password"];
            }
            return View(user);
        }

        // [HttpPost("Loginpage")]
        // public async Task<IActionResult> Loginpage(LoginVM model)
        // {
        //     if (!ModelState.IsValid)
        //     {
        //         return View(model);
        //     }

        //     var user = _userService.AuthenticateUser(model.Email, model.Password);
        //     if (user == null)
        //     {
        //         ModelState.AddModelError(string.Empty, "Invalid email or password.");
        //         return View(model);
        //     }

        //     var token = _userService.AuthenticateUser(model.Email, model.Password);

        //     if (model.RememberMe)
        //     {
        //         var cookieOptions = new CookieOptions
        //         {
        //             Expires = DateTime.Now.AddDays(30)
        //         };
        //         Response.Cookies.Append("Email", model.Email, cookieOptions);
        //         Response.Cookies.Append("UserToken", "someUniqueToken", cookieOptions);
        //     }
        //     else
        //     {
        //         Response.Cookies.Delete("Email");
        //         Response.Cookies.Delete("UserToken");
        //     }
        //     // Store JWT in Session
        //     HttpContext.Session.SetString("AuthToken", token);

        //     return RedirectToAction("Dashboard", "Home");
        // }
        [HttpPost("Loginpage")]
        public async Task<IActionResult> Loginpage(LoginVM model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var token = _userService.AuthenticateUser(model.Email, model.Password);
            if (token == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid email or password.");
                return View(model);
            }

            if (model.RememberMe)
            {
                var cookieOptions = new CookieOptions
                {
                    Expires = DateTime.Now.AddDays(30)
                };
                Response.Cookies.Append("Email", model.Email, cookieOptions);
                Response.Cookies.Append("AuthToken", token);
            }
            else
            {
                Response.Cookies.Delete("Email");
            }
            // Store JWT in Session
            HttpContext.Session.SetString("AuthToken", token);
            // Return the token to the client
            return RedirectToAction("Dashboard", "Home");
        }
        // [HttpPost("Loginpage")]
        // public async Task<IActionResult> Loginpage(LoginVM model)
        // {
        //     if (!ModelState.IsValid)
        //     {
        //         return View(model);
        //     }

        //     var user = await _userService.AuthenticateUser(model.Email, model.Password);
        //     if (user == null)
        //     {
        //         ModelState.AddModelError(string.Empty, "Invalid email or password.");
        //         return View(model);
        //     }

        //     if (model.RememberMe)
        //     {
        //         var cookieOptions = new CookieOptions
        //         {
        //             Expires = DateTime.Now.AddDays(30)
        //         };
        //         Response.Cookies.Append("Email", model.Email, cookieOptions);
        //         Response.Cookies.Append("Password", model.Password, cookieOptions);
        //     }
        //     else
        //     {
        //         Response.Cookies.Delete("Email");
        //         Response.Cookies.Delete("Password");
        //     }

        //     return RedirectToAction("Userpage", "User");
        // }

        // [HttpGet("Forgotpasswordpage")]
        public IActionResult Forgotpasswordpage()
        {

            return View();
        }

        // [HttpPost("Forgotpasswordpage")]
        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _userService.GenerateResetTokenAsync(email);
            // Console.WriteLine(user.ResetToken);
            // Console.WriteLine(user.ResetTokenExpirytime);
            if (user != null)
            {
                // Send email with reset link
                ViewBag.Message = "A reset link has been sent to your email.";
                await SendResetEmail(user.Email, user.ResetToken);
            }

            return View("Forgotpasswordpage");
        }


        // [HttpGet("ResetPassword")]
        public IActionResult Resetpasswordpage(string email, string token)
        {
            // var model = new ResetPasswordVM { Email = email, Token = token };

            Console.WriteLine("------------------------------------------------------12323-");
            // Console.WriteLine(model.Token);

            var user = _userService.GetUserByToken(token);
            // Console.WriteLine();
            if (user == null)
            {
                // Handle case when user is not found
                return NotFound();
            }

            var model = new ResetPasswordVM
            {
                Email = email,
                Token = token
            };
            Console.WriteLine(model.Token);
            Console.WriteLine("Auth Controller:  " + model.Email);
            Console.WriteLine(model.Token);

            return View(model);
        }

        // [HttpPost("ResetPassword")]
        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordVM model)
        {
            Console.WriteLine("In resetPage");
            Console.WriteLine(model.Email);
            if (!ModelState.IsValid)
            {
                Console.WriteLine("ModelState is not valid.");
                return View(model);
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                ModelState.AddModelError("", "Passwords do not match.");
                Console.WriteLine("Passwords do not match.");
                return View(model);
            }
            Console.WriteLine(model.Email);
            var result = await _userService.ResetPasswordAsync(model.Email, model.Token, model.NewPassword);
            Console.WriteLine("EMAIL:" + model.Email);

            if (result)
            {
                ViewBag.Message = "A Password Reset Successful.";
                Console.WriteLine("Password reset process successful.");
                return RedirectToAction("Loginpage", "Authentication");
            }

            ModelState.AddModelError("", "Invalid token or the token has expired.");
            Console.WriteLine("Invalid token or the token has expired.");
            return View("Resetpasswordpage", model);
        }



        // [HttpPost("ResetPassword")]
        // public async Task<IActionResult> ResetPassword(ResetPasswordVM model)
        // {
        //     if (!ModelState.IsValid)
        //     {
        //         Console.WriteLine("ModelState is not valid.");
        //         return View(model);
        //     }

        //     if (model.NewPassword != model.ConfirmPassword)
        //     {
        //         ModelState.AddModelError("", "Passwords do not match.");
        //         Console.WriteLine("Passwords do not match.");
        //         return View(model);
        //     }
        //     Console.WriteLine("In Controller");
        //     Console.WriteLine(model.Email);
        //     Console.WriteLine(model.Token);
        //     Console.WriteLine(model.NewPassword);
        //     var result = await _userService.ResetPasswordAsync(model.Email, model.Token, model.NewPassword);

        //     if (result)
        //     {
        //         Console.WriteLine("Password successfully reset.");
        //         return RedirectToAction("Loginpage", "Authentication");
        //     }


        //     ModelState.AddModelError("", "Invalid token or the token has expired.");
        //     Console.WriteLine("Invalid token or the token has expired.");
        //     return View("resetpasswordpage", model);
        // }



        private async Task SendResetEmail(string email, string token)
        {
            var resetLink = Url.Action("Resetpasswordpage", "Authentication", new { token, email }, Request.Scheme);
            var message = new MailMessage("test.dotnet@etatvasoft.com", email);
            message.To.Add(new MailAddress(email));
            message.Subject = "Password Reset Request";
            message.Body = $"Please reset your password by clicking here: <a href='{resetLink}'>link</a>";
            message.IsBodyHtml = true;

            using (var smtp = new SmtpClient())
            {
                smtp.Host = "mail.etatvasoft.com"; // Replace with your SMTP server
                smtp.Port = 587; // Replace with your SMTP port
                smtp.EnableSsl = true;
                smtp.Credentials = new NetworkCredential("test.dotnet@etatvasoft.com", "P}N^{z-]7Ilp"); // Replace with your email and password

                await smtp.SendMailAsync(message);
            }
        }
    }
}


// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Mvc;
// using System;
// using Microsoft.EntityFrameworkCore;
// using System.Linq;
// using Microsoft.AspNetCore.Http;
// using System.Net.Mail;
// using System.Net;
// using System.Security.Cryptography;
// using System.Text;
// using System.Threading.Tasks;
// using PizzaShop.ViewModel;
// using BLL.Services;

// namespace PizzaShop.Controllers
// {
//     public class AuthenticationController : Controller
//     {
//         private readonly IUserService _userService;

//         public AuthenticationController(IUserService userService)
//         {
//             _userService = userService;
//         }

//         [HttpGet("Loginpage")]
//         public IActionResult Loginpage()
//         {
//             var user = new LoginModel();
//             if (Request.Cookies["Email"] != null && Request.Cookies["Password"] != null)
//             {
//                 user.Email = Request.Cookies["Email"];
//                 user.Password = Request.Cookies["Password"];
//             }
//             return View(user);
//         }

//         [HttpPost("Loginpage")]
//         public async Task<IActionResult> Loginpage(LoginModel model)
//         {
//             if (!ModelState.IsValid)
//             {
//                 return View(model);
//             }

//             var authenticatedUser = await _userService.AuthenticateUser(model);
//             if (!authenticatedUser.IsAuthenticated)
//             {
//                 ModelState.AddModelError(string.Empty, "Invalid email or password.");
//                 return View(model);
//             }

//             if (model.RememberMe)
//             {
//                 var cookieOptions = new CookieOptions
//                 {
//                     Expires = DateTime.Now.AddDays(30)
//                 };
//                 Response.Cookies.Append("Email", model.Email, cookieOptions);
//                 Response.Cookies.Append("Password", model.Password, cookieOptions);
//             }
//             else
//             {
//                 Response.Cookies.Delete("Email");
//                 Response.Cookies.Delete("Password");
//             }

//             return RedirectToAction("Userpage", "User");
//         }

//         [HttpGet("Forgotpasswordpage")]
//         public IActionResult Forgotpasswordpage()
//         {
//             return View();
//         }

//         [HttpPost("Forgotpasswordpage")]
//         public async Task<IActionResult> ForgotPassword(string email)
//         {
//             var resetPasswordModel = await _userService.GenerateResetTokenAsync(email);
//             if (resetPasswordModel != null)
//             {
//                 // Send email with reset link
//                 await SendResetEmail(resetPasswordModel.Email, resetPasswordModel.Token);
//             }

//             return View("ForgotPasswordConfirmation");
//         }

//         [HttpGet("ResetPassword")]
//         public IActionResult ResetPassword(string token)
//         {
//             var model = new ResetPasswordViewModel { Token = token };
//             return View(model);
//         }

//         [HttpPost("ResetPassword")]
//         public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
//         {
//             if (await _userService.ResetPasswordAsync(model))
//             {
//                 return RedirectToAction("Loginpage", "Authentication");
//             }
//             ModelState.AddModelError("", "Invalid token or passwords do not match.");
//             return View(model);
//         }

//         private async Task SendResetEmail(string email, string token)
//         {
//             var resetLink = Url.Action("ResetPassword", "Authentication", new { token }, Request.Scheme);
//             var message = new MailMessage();
//             message.To.Add(new MailAddress(email));
//             message.Subject = "Password Reset Request";
//             message.Body = $"Please reset your password by clicking here: <a href='{resetLink}'>link</a>";
//             message.IsBodyHtml = true;

//             using (var smtp = new SmtpClient())
//             {
//                 smtp.Host = "smtp.your-email-provider.com"; // Replace with your SMTP server
//                 smtp.Port = 587; // Replace with your SMTP port
//                 smtp.EnableSsl = true;
//                 smtp.Credentials = new NetworkCredential("your-email@example.com", "your-email-password"); // Replace with your email and password

//                 await smtp.SendMailAsync(message);
//             }
//         }
//     }
// }


// namespace PizzaShop.Controllers
// {
//     public class AuthenticationController : Controller
//     {
//         private readonly PizzaShopContext _context;

//         public AuthenticationController(PizzaShopContext context)
//         {
//             _context = context;
//         }

//         // Display the login page
//         [HttpGet("Loginpage")]
//         public IActionResult Loginpage()
//         {
//             var user = new LoginModel();
//             if (Request.Cookies["Email"] != null && Request.Cookies["Password"] != null)
//             {
//                 user.Email = Request.Cookies["Email"];
//                 user.Password = Request.Cookies["Password"];
//                 // return RedirectToAction("Userpage", "User");
//             }
//             return View(user);
//         }

//         // Process the login form
//         [HttpPost("Loginpage")]
//         public async Task<IActionResult> Loginpage(LoginModel model)
//         {
//             if (!ModelState.IsValid)
//             {
//                 return View(model);
//             }

//             var user = await _context.Users
//                 .FirstOrDefaultAsync(u => u.Email == model.Email && u.Password == model.Password);

//             if (user == null)
//             {
//                 ModelState.AddModelError(string.Empty, "Invalid email or password.");
//                 return View(model);
//             }

//             if (model.RememberMe)
//             {
//                 var cookieOptions = new CookieOptions
//                 {
//                     Expires = DateTime.Now.AddDays(30)
//                 };
//                 Response.Cookies.Append("Email", user.Email, cookieOptions);
//                 Response.Cookies.Append("Password", user.Password, cookieOptions);
//             }
//             else
//             {
//                 Response.Cookies.Delete("Email");
//                 Response.Cookies.Delete("Password");
//             }

//             // Handle successful login (e.g., set authentication cookie, redirect to user page)
//             return RedirectToAction("Userpage", "User");
//         }

//         [HttpGet("Forgotpasswordpage")]
//         public IActionResult Forgotpasswordpage()
//         {
//             return View();
//         }



//         [HttpPost]

//         public async Task<IActionResult> ForgotPassword(string email)
//         {
//             var user = await _context.Users.SingleOrDefaultAsync(u => u.Email == email);
//             if (user != null)
//             {
//                 // Generate a reset token
//                 user.ResetToken = GenerateResetToken();
//                 user.ResetTokenExpiration = DateTime.UtcNow.AddHours(1);
//                 await _context.SaveChangesAsync();

//                 // Send email with reset link
//                 await SendResetEmail(user.Email, user.ResetToken);
//             }

//             // Show a message that an email has been sent
//             return View("ForgotPasswordConfirmation");
//         }

//         [HttpGet]
//         public async Task<IActionResult> ResetPassword(string token)
//         {
//             var user = await _context.Users.SingleOrDefaultAsync(u => u.ResetToken == token && u.ResetTokenExpiration > DateTime.UtcNow);
//             if (user == null)
//             {
//                 return NotFound();
//             }

//             var model = new ResetPasswordViewModel { Token = token };
//             return View(model);
//         }

//         [HttpPost]
//         public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
//         {
//             var user = await _context.Users.SingleOrDefaultAsync(u => u.ResetToken == model.Token && u.ResetTokenExpiration > DateTime.UtcNow);
//             if (user == null)
//             {
//                 return NotFound();
//             }

//             if (model.NewPassword != model.ConfirmPassword)
//             {
//                 ModelState.AddModelError("", "Passwords do not match.");
//                 return View(model);
//             }

//             // Hash the new password and save it
//             user.Password = HashPassword(model.NewPassword);
//             user.ResetToken = null; // Clear the reset token
//             user.ResetTokenExpiration = null; // Clear the expiration
//             await _context.SaveChangesAsync();

//             return RedirectToAction("Login", "Account");
//         }

//         private string GenerateResetToken()
//         {
//             var tokenData = new byte[32];
//             using (var rng = RandomNumberGenerator.Create())
//             {
//                 rng.GetBytes(tokenData);
//             }

//             return Convert.ToBase64String(tokenData);
//         }


//         private async Task SendResetEmail(string email, string token)
//         {
//             var resetLink = Url.Action("ResetPassword", "Authentication", new { token }, Request.Scheme);
//             var message = new MailMessage();
//             message.To.Add(new MailAddress(email));
//             message.Subject = "Password Reset Request";
//             message.Body = $"Please reset your password by clicking here: <a href='{resetLink}'>link</a>";
//             message.IsBodyHtml = true;

//             using (var smtp = new SmtpClient())
//             {
//                 smtp.Host = "mail.etatvasoft.com"; // Replace with your SMTP server
//                 smtp.Port = 587; // Replace with your SMTP port
//                 smtp.EnableSsl = true;
//                 smtp.Credentials = new NetworkCredential("tatvasoft.pct71@outlook.com", "!@34QWer"); // Replace with your email and password

//                 await smtp.SendMailAsync(message);
//             }
//         }


//         private string HashPassword(string password)
//         {
//             // Implement your password hashing logic here
//             // For example, using BCrypt or any other hashing algorithm
//             using (var hmac = new HMACSHA256())
//             {
//                 var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
//                 return Convert.ToBase64String(hash);
//             }
//         }


//         // [HttpGet("ResetPassword")]
//         // public IActionResult ResetPassword(string code)
//         // {
//         //     var model = new ResetPasswordModel { ResetPasswordCode = code };
//         //     return View(model);
//         // }

//         // [HttpPost("ResetPassword")]
//         // public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
//         // {
//         //     if (!ModelState.IsValid)
//         //     {
//         //         return View(model);
//         //     }

//         //     var user = await _context.Users.FirstOrDefaultAsync(u => u.ResetPasswordCode == model.ResetPasswordCode);
//         //     if (user == null)
//         //     {
//         //         ModelState.AddModelError(string.Empty, "Invalid reset password code.");
//         //         return View(model);
//         //     }

//         //     if (model.NewPassword != model.ConfirmPassword)
//         //     {
//         //         ModelState.AddModelError(string.Empty, "Passwords do not match.");
//         //         return View(model);
//         //     }

//         //     user.Password = model.NewPassword; // Update with hashing in a real application
//         //     user.ResetPasswordCode = null; // Clear the reset code
//         //     _context.Update(user);
//         //     await _context.SaveChangesAsync();

//         //     ViewBag.Message = "Password has been reset successfully.";
//         //     return RedirectToAction("Loginpage");
//         // }
//     }
// }
