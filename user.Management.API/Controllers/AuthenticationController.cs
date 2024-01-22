using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Text;
using user.Management.API.Models;
using user.Management.API.Models.Authentication;
using user.Management.API.Models.Authentication.Login;
using user.Management.API.Models.Authentication.Signup;
using User.Management.Service.Models;
using User.Management.Service.Services;
using static System.Net.WebRequestMethods;

namespace user.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(UserManager<IdentityUser> userManager,
                                          RoleManager<IdentityRole> roleManager,
                                          SignInManager<IdentityUser> signInManager,
                                          IEmailService emailService, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _configuration = configuration;
            _signInManager = signInManager;
        }

        [HttpPost]

        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)

        {
            // Check if user exists

            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {

                return StatusCode(StatusCodes.Status403Forbidden, new Response { Status = "Error", Message = "User already exists" });
            }

            // if does not exist add user in database

            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true /*Enabling Two Factor Authentication*/
            };

            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);

                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to register" });
                }
                // Assign a role that we want
                await _userManager.AddToRoleAsync(user, role);

                // Add token to verify email

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token, email = user.Email }, Request.Scheme);

                var message = new Message(new string[] { user.Email! }, "Confirmation email link", confirmationLink!);

                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"User created successfully and Email sent to {user.Email}" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "This role does not exist" });
            }

        }

        /*        [HttpGet]

                public IActionResult TestEmail()
                {
                    var message = new Message(new string[] {"vaibhav_chavan@idealake.com"}, "Test", "<h1>buenos dias.</h1>");


                     _emailService.SendEmail(message);
                    return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email sent successfully" });

                }*/

        [HttpGet("ConfirmEmail")]

        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email verified successfully" });

                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "This user does not exist" });

        }


        [HttpPost]
        [Route("login")]

        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)

        {
            // checking the user

            var user = await _userManager.FindByNameAsync(loginModel.Username);
            // checking the password

            if (user.TwoFactorEnabled)
            {

                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, false);
                var otp = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                var message = new Message(new string[] { user.Email! }, "Your 2FA Login OTP is : ", otp!);

                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"OTP is sent to {user.Email}" });

            }

            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                // claimlist creation

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                var userRoles = await _userManager.GetRolesAsync(user);

                // we add roles to the claim list

                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                // generate the token with claims

                var jwtToken = GetToken(authClaims);

                // return the token

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    expiration = jwtToken.ValidTo
                }
                    );

            }

            return Unauthorized();
        }

        [HttpPost]
        [Route("login-2FA")]

        public async Task<IActionResult> LoginWithOtp(string code, string username)

        {
            var user = await _userManager.FindByNameAsync(username);

            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);

            if (signIn.Succeeded)
            {


                if (user != null)
                {
                    // claimlist creation

                    var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                    var userRoles = await _userManager.GetRolesAsync(user);

                    // we add roles to the claim list

                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }


                    // generate the token with claims

                    var jwtToken = GetToken(authClaims);

                    // return the token

                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo
                    }
                        );

                }


            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Invalid OTP" });

        }


        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]

        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordlink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password Link: ", forgotPasswordlink!);

                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password changed request is sent on email: {user.Email}, Kindly check and click on received link." });
            }
            return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = $"Couldn't send link to email {user.Email}, please try again." });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new
            {
                model
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]

        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {

                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password is changed for user {user.UserName}" });
            }
            return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = $"Couldn't send link to email {user.Email}, please try again." });
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }
    }
}
