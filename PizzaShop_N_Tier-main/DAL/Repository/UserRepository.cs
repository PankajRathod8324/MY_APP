using DAL.Interfaces;
using DAL.Models;
using Microsoft.EntityFrameworkCore;

namespace DAL.Repository;

public class UserRepository : IUserRepository
{
    private readonly PizzaShopContext _context;

    public UserRepository(PizzaShopContext context)
    {
        _context = context;
    }

    public  User GetUserByEmailAndPassword(string email, string password)
    {
        return  _context.Users.FirstOrDefault(u => u.Email == email && u.Password == password);
    }


    public  User GetUserByEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
        {
            Console.WriteLine("Email is null or empty.");
            return null;
        }

        Console.WriteLine("Fetching user with email: " + email);

        if (_context == null)
        {
            Console.WriteLine("Database context is null.");
            throw new NullReferenceException("Database context is not initialized.");
        }

        // var user = _context.Users.FirstOrDefault(u => u.Email == email);
        
        var user = _context.Users.FirstOrDefault(u => u.Email == email);
        Console.WriteLine(user);

        Console.WriteLine(user != null ? "User found." : "User not found.");
        return user;
    }


    public  User GetUserByToken(string token)
    {
        var user =  _context.Users.SingleOrDefault(u => u.ResetToken == token);
        Console.WriteLine("GetUserBy Token"+user.Email);
        return user;
    }

    public  string GetUserRole(string email)
    {
        var userRole =  (from user in _context.Users
                          join role in _context.Roles on user.RoleId equals role.RoleId
                          where user.Email == email
                          select role.RoleName).FirstOrDefault();
        return userRole;
    }


    public void UpdateUser(User user)
    {

        _context.Users.Update(user);
        _context.SaveChanges();
    }

}


