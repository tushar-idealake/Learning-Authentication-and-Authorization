﻿using System.ComponentModel.DataAnnotations;

namespace user.Management.API.Models.Authentication
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User Name is required")]

        public string? Username { get; set; }

        [EmailAddress]
        
        [Required(ErrorMessage = "Email is required")]

        public string? Email { get; set; } 
        
        [Required(ErrorMessage = "Password is required")]

        public string? Password { get; set; }
    }
}
