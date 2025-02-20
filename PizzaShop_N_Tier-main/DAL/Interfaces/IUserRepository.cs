using System.Threading.Tasks;
using DAL.Models;

namespace DAL.Interfaces;
public interface IUserRepository
{
    User GetUserByEmailAndPassword(string email, string password);
    User GetUserByEmail(string email);
    User GetUserByToken(string token);
    string GetUserRole(string email);
    void UpdateUser(User user);

}
