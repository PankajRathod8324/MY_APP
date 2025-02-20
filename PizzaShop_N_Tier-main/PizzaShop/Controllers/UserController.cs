// using System;
// using System.Collections.Generic;
// using System.Linq;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.AspNetCore.Mvc.Rendering;
// using Microsoft.EntityFrameworkCore;
// using PizzaShop.Models;
// using System.Diagnostics;
// using DAL.Models;


// namespace PizzaShop.Controllers;

// public class UserController : Controller
// {
//     private readonly PizzaShopContext _context;

//     public UserController(PizzaShopContext context)
//     {
//         _context = context;
//     }


//     public async Task<IActionResult> Userpage()
//     {
//         return View(await _context.Users.ToListAsync());
//     }

    
   
// }