using API.Models.Response;
using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.IdentityModel.Tokens;
using Service.Models.Auth.Login;
using Service.Models.Auth.Register;
using Service.Models.Auth.User;
using Service.Models.Entity;
using Service.Services.IService;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IEmailService _emailService;
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;

        public AuthenticationController(IEmailService emailService, IAuthService authService, IConfiguration configuration)
        {
            _emailService = emailService;
            _authService = authService;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var response = await _authService.RegisterNewUser(model);

            if (response.isSuccess)
            {
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { token = response.Data.Token, email = model.Email }, Request.Scheme);
                var emailMessage = new EmailMessage(new string[] { model.Email }, "Email Confirmation Link", confirmationLink!);
                _emailService.SendEmail(emailMessage);

                return Ok(new CommonResponseModel
                {
                    ResponseCode = response.HttpCode,
                    Message = response.Message,
                    Data = response?.Data ?? new object(),
                    Errors = response?.Errors
                });
            }

            return BadRequest(new CommonResponseModel
            {
                ResponseCode = response.HttpCode,
                Message = response?.Message ?? "Message Null",
                Data = response?.Data ?? new object(),
                Errors = response?.Errors
            });
        }

        [HttpPost("register-admin")]
        public async Task<IActionResult> RegisterAdmin(RegisterModel model)
        {
            var response = await _authService.RegisterAdmin(model);
            return null;
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var response = await _authService.ConfirmEmailVerification(token, email);
            if (response.isSuccess == true)
            {
                return Ok(new CommonResponseModel
                {
                    ResponseCode = response.HttpCode,
                    Message = response.Message,
                    Data = response?.Data ?? new object(),
                    Errors = response?.Errors
                });
            }

            return BadRequest(new CommonResponseModel
            {
                ResponseCode = response.HttpCode,
                Message = response?.Message ?? "Message Null",
                Data = response?.Data ?? new object(),
                Errors = response?.Errors
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var twoFactorEnabledLogin = await _authService.Login(model);

            if (twoFactorEnabledLogin.isSuccess)
            {
                return Ok(new CommonResponseModel
                {
                    ResponseCode = twoFactorEnabledLogin.HttpCode,
                    Message = twoFactorEnabledLogin.Message,
                    Data = twoFactorEnabledLogin?.Data ?? new object(),
                    Errors = twoFactorEnabledLogin?.Errors
                });
            }

            return BadRequest(new CommonResponseModel
            {
                ResponseCode = twoFactorEnabledLogin.HttpCode,
                Message = twoFactorEnabledLogin?.Message ?? "Message Null",
                Data = twoFactorEnabledLogin?.Data ?? new object(),
                Errors = twoFactorEnabledLogin?.Errors
            });
        }

        [HttpPost("login-OTP")]
        public async Task<IActionResult> LoginOTP(string code, string username)
        {
            var login = await _authService.LoginWithOTP(code, username);

            if (login.isSuccess)
            {
                return Ok(new CommonResponseModel
                {
                    ResponseCode = login.HttpCode,
                    Message = login.Message,
                    Data = login?.Data ?? new object { },
                    Errors = login?.Errors
                });
            }

            return BadRequest(new CommonResponseModel
            {
                ResponseCode = login.HttpCode,
                Message = login?.Message ?? "Message Null",
                Data = login?.Data ?? new object(),
                Errors = login?.Errors
            });
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var response = await _authService.GenerateForgotPasswordLink(email);

            if (response.isSuccess)
            {
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token = response.Data, email }, Request.Scheme);
                var message = new EmailMessage(new string[] { email }, "Forgot Password Link", forgotPasswordLink!);
                _emailService.SendEmail(message);

                return Ok(new CommonResponseModel
                {
                    ResponseCode = response.HttpCode,
                    Message = $"Reset password link has been sent to your email {email}",
                    Data = response?.Data ?? new object(),
                    Errors = response?.Errors
                });
            }

            return BadRequest(new CommonResponseModel
            {
                ResponseCode = response.HttpCode,
                Message = response?.Message ?? "Couldn't send password reset link.",
                Data = response?.Data ?? new object(),
                Errors = response?.Errors
            });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword
            {
                Token = token,
                Email = email
            };

            return Ok(new
            {
                model
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword model)
        {
            var response = await _authService.ResetPasswordAsync(model);

            if (response.isSuccess)
            {
                return Ok(new CommonResponseModel
                {
                    ResponseCode = response.HttpCode,
                    Message = response.Message,
                    Data = response?.Data ?? new object(),
                    Errors = response?.Errors
                });
            }
            return BadRequest(new CommonResponseModel
            {
                ResponseCode = response.HttpCode,
                Message = response?.Message,
                Data = response?.Data,
                Errors = response?.Errors
            });
        }
    }
}
