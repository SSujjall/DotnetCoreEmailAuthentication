using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.Models.Auth.Register
{
    public class RegisterResponse
    {
        public string? Token { get; set; }
        public IdentityUser? User { get; set; }
    }
}
