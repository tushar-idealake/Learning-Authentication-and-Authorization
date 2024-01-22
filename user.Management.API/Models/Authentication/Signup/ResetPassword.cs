using System.ComponentModel.DataAnnotations;

namespace user.Management.API.Models.Authentication.Signup
{
    public class ResetPassword
    {
        [Required]

        public string Password { get; set; } = null;

        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]

        public string ConfirmPassword { get; set; }
        public string Email { get; set;}
        public string Token { get; set;}
    }
}
