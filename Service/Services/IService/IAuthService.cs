using Microsoft.AspNetCore.Identity;
using Service.Models.Auth.Login;
using Service.Models.Auth.Register;
using Service.Models.Auth.User;
using Service.Models.Response;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Service.Services.IService
{
    public interface IAuthService
    {
        Task<ServiceResponse<RegisterResponse>> RegisterNewUser(RegisterModel model);
        Task<ServiceResponse<RegisterResponse>> RegisterAdmin(RegisterModel model);
        Task<ServiceResponse<object>> Login(LoginModel model);
        Task<ServiceResponse<object>> LoginWithOTP(string code, string username);
        Task<ServiceResponse<object>> ConfirmEmailVerification(string token, string email);
        Task<ServiceResponse<string>> GenerateForgotPasswordLink(string email);
        Task<ServiceResponse<object>> ResetPasswordAsync(ResetPassword model);
    }
}
