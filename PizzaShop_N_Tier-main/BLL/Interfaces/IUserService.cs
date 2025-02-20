using System.Threading.Tasks;
using DAL.Models;

namespace BLL.Interfaces;
public interface IUserService
{
 
    string AuthenticateUser(string email, string password);

    Task<User> GetUserByEmailAsync(string email);

    User GetUserByToken(string token);
    Task<User> GenerateResetTokenAsync(string email);
    Task<bool> ResetPasswordAsync(string email, string token, string newPassword);
}