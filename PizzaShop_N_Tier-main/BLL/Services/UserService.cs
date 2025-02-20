using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using DAL.Models;
using DAL.Interfaces;
using Microsoft.EntityFrameworkCore;
using BLL.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;

namespace BLL.Services;

public class UserService : IUserService
{
    private readonly IUserRepository _userRepository;
    private readonly IConfiguration _configuration;

    public UserService(IUserRepository userRepository, IConfiguration configuration)
    {
        _userRepository = userRepository;
        _configuration = configuration;
    }

    // public async Task<User> AuthenticateUserAsync(string email, string password)
    // {
    //     return await _userRepository.GetUserByEmailAndPasswordAsync(email, password);
    // }

    public string AuthenticateUser(string email, string password)
    {
        // && BCrypt.Net.BCrypt.Verify(password, user.Password)
        var user = _userRepository.GetUserByEmail(email);
        if (user != null)
        {
            var userRole = _userRepository.GetUserRole(email);
            return GenerateJwtToken(email, userRole);
        }
        return null;

    }
    private string GenerateJwtToken(string email, string role)
    {
        var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]);
        Console.WriteLine("Role Name : " + role);
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Role, role)
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(int.Parse(_configuration["Jwt:ExpiryMinutes"])),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenValue = tokenHandler.WriteToken(token);

        // Debugging: Print the token to verify its contents
        Console.WriteLine("Generated JWT Token: " + tokenValue);

        // Read the token to verify the claims
        var jwtToken = tokenHandler.ReadToken(tokenValue) as JwtSecurityToken;
        var roleName = jwtToken?.Claims.FirstOrDefault(c => c.Type == "role")?.Value;
        
        if (jwtToken != null)
        {
            // Extract claims
            var claims1 = jwtToken.Claims;

            // Example: Extract specific claim value
            var userId = claims1.FirstOrDefault(c => c.Type == "role")?.Value;
            var userEmail = claims1.FirstOrDefault(c => c.Type == "email")?.Value;

            Console.WriteLine($"User ID: {userId}");
            Console.WriteLine($"User Email: {userEmail}");
        }
        else
        {
            Console.WriteLine("Invalid JWT token.");
        }
       

        // Debugging: Print the role to verify it's correctly read
        Console.WriteLine("Extracted Role from Token: " + roleName);

        return tokenValue;
    }
    public async Task<User> GetUserByEmailAsync(string email)
    {
        return _userRepository.GetUserByEmail(email);

    }


    public User GetUserByToken(string token)
    {
        return _userRepository.GetUserByToken(token);
    }
    public async Task<User> GenerateResetTokenAsync(string email)
    {
        var user = _userRepository.GetUserByEmail(email);
        Console.WriteLine(user.ResetToken);
        Console.WriteLine("In Service " + user.Email);
        if (user != null)
        {
            // Check if the existing token is still valid
            // if (user.ResetTokenExpirytime > DateTime.UtcNow)
            // {
            //     Console.WriteLine("Existing valid token found, not generating a new one.");
            //     return user; // Reuse the existing valid token
            // }

            // Generate a new token and set the expiration time
            user.ResetToken = GenerateResetToken();
            user.ResetTokenExpirytime = DateTime.UtcNow.AddHours(1);
            Console.WriteLine("New token generated: " + user.ResetToken);
            Console.WriteLine("Token expiry time (UTC): " + user.ResetTokenExpirytime);
            _userRepository.UpdateUser(user);
            Console.WriteLine(user.Email);
            Console.WriteLine(user.ResetToken);
            Console.WriteLine("User updated with new token.");
        }
        return user;
    }


    public async Task<bool> ResetPasswordAsync(string email, string token, string newPassword)
    {
        if (string.IsNullOrEmpty(email))
        {
            Console.WriteLine("In service");
            Console.WriteLine("Email is null or empty.");
            return false;
        }

        if (_userRepository == null)
        {
            Console.WriteLine("User repository is null.");
            throw new NullReferenceException("User repository is not initialized.");
        }

        var user = _userRepository.GetUserByEmail(email);
        if (user == null)
        {
            Console.WriteLine("User not found.");
            return false;
        }

        Console.WriteLine("Token from user: " + user.ResetToken);
        Console.WriteLine(token);
        Console.WriteLine("Token expiry time (UTC): " + user.ResetTokenExpirytime);
        Console.WriteLine(DateTime.UtcNow);

        if (user.ResetToken == token && user.ResetTokenExpirytime > DateTime.UtcNow)
        {
            Console.WriteLine(newPassword);
            user.Password = HashPassword(newPassword);
            Console.WriteLine(user.Password);
            user.ResetToken = null;
            user.ResetTokenExpirytime = null;
            _userRepository.UpdateUser(user);
            Console.WriteLine("Password reset successful. User updated.");
            return true;
        }
        else
        {
            Console.WriteLine("Invalid token or token has expired.");
        }
        return false;
    }

    private string GenerateResetToken()
    {
        var tokenData = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(tokenData);
        }
        return Convert.ToBase64String(tokenData);
    }

    private string HashPassword(string password)
    {
        // using (var hmac = new HMACSHA256())
        // {
        //     var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
        //     return Convert.ToBase64String(hash);
        // }
        return BCrypt.Net.BCrypt.HashPassword(password);
    }

}