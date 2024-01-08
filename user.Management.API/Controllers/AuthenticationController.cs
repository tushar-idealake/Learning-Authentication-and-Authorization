using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using user.Management.API.Models;
using user.Management.API.Models.Authentication;
using User.Management.Service.Models;
using User.Management.Service.Services;

namespace user.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;

        public AuthenticationController(UserManager<IdentityUser> userManager, 
                                          RoleManager<IdentityRole> roleManager,
                                          IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        [HttpPost]

        public async Task<IActionResult> Register ([FromBody] RegisterUser registerUser, string role)

        {
            // Check if user exists

            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null){

                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User already exists" });
            }

            // if does not exist add user in database

            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username
            };

            if(await _roleManager.RoleExistsAsync(role))
            {
            var result = await _userManager.CreateAsync(user, registerUser.Password);

            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to register" });
            }
                // Assign a role that we want
             await _userManager.AddToRoleAsync(user, role);

             return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "User created successfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "This role does not exist" });
            }

        }

        [HttpGet]

        public IActionResult TestEmail()
        {
            var message = new Message(new string[] {"vaibhav_chavan@idealake.com"}, "Test", "<h1>buenos dias.</h1>");


             _emailService.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email sent successfully" });

        }
    }
}
