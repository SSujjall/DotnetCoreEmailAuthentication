using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Service.Models.Auth.Login;
using Service.Models.Auth.Register;
using Service.Models.Auth.User;
using Service.Models.Entity;
using Service.Models.Enums;
using Service.Models.Response;
using Service.Services.IService;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Service.Services.Service
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly IJwtTokenService _jwtTokenService;

        public AuthService(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager,
                            SignInManager<IdentityUser> signInManager, IEmailService emailService,
                            IJwtTokenService jwtTokenService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _jwtTokenService = jwtTokenService;
        }

        private async Task AssignRoleToUser(IdentityUser user, string role)
        {
            if (await _roleManager.RoleExistsAsync(role))
            {
                if (!await _userManager.IsInRoleAsync(user, role))
                {
                    await _userManager.AddToRoleAsync(user, role);
                }
            }
        }

        public async Task<ServiceResponse<RegisterResponse>> RegisterNewUser(RegisterModel model)
        {
            var searchEmail = await _userManager.FindByEmailAsync(model.Email);

            if (searchEmail != null)
            {
                return new ServiceResponse<RegisterResponse>
                {
                    HttpCode = HttpStatusCode.Conflict,
                    Message = "User already exists",
                    isSuccess = false
                };
            }

            var user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                TwoFactorEnabled = true
            };
            var result = await _userManager.CreateAsync(user, model.Password);

            //store errors if any
            var errorList = result.Errors.Select(x => x.Description).ToList();

            if (result.Succeeded)
            {
                await AssignRoleToUser(user, Roles.User.ToString());

                var emailToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                return new ServiceResponse<RegisterResponse>
                {
                    HttpCode = HttpStatusCode.OK,
                    Message = "Confirmation link sent to email.",
                    Data = new RegisterResponse
                    {
                        Token = emailToken,
                        User = user
                    },
                    Errors = null,
                    isSuccess = true
                };
            }

            return new ServiceResponse<RegisterResponse>
            {
                HttpCode = HttpStatusCode.BadRequest,
                Message = "Error creating user.",
                Errors = errorList,
                isSuccess = false
            };
        }

        public Task<ServiceResponse<RegisterResponse>> RegisterAdmin(RegisterModel model)
        {
            throw new NotImplementedException();
        }

        public async Task<ServiceResponse<object>> ConfirmEmailVerification(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded)
                {
                    return new ServiceResponse<object>
                    {
                        HttpCode = HttpStatusCode.OK,
                        Message = "Email Verified Successfully.",
                        isSuccess = true
                    };
                }
            }

            return new ServiceResponse<object>
            {
                HttpCode = HttpStatusCode.BadRequest,
                Message = "Email verification unsuccessful.",
                isSuccess = false
            };
        }

        public async Task<ServiceResponse<object>> Login(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, model.Password, false, true);

                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var message = new EmailMessage(new string[] { user.Email! }, "OTP Confirmation", token);
                _emailService.SendEmail(message);

                return new ServiceResponse<object>
                {
                    HttpCode = HttpStatusCode.Created,
                    Message = $"OTP Sent to your email {user.Email}",
                    isSuccess = true
                };
            }

            // If user has not enabled two factor then skip the otp generation
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRole = (await _userManager.GetRolesAsync(user)).FirstOrDefault();

                // claim list creation
                var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(ClaimTypes.Role, userRole)
                    };

                // generate the token with the claims
                var jwtToken = _jwtTokenService.GetToken(authClaims);

                return new ServiceResponse<object>
                {
                    HttpCode = HttpStatusCode.OK,
                    Message = "Login successful.",
                    Data = new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo,
                        user = user.UserName
                    },
                    isSuccess = true
                };
            }

            return new ServiceResponse<object>
            {
                HttpCode = HttpStatusCode.Unauthorized,
                Message = "User does not exist.",
                isSuccess = false
            };
        }

        public async Task<ServiceResponse<object>> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);

            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    // claim list creation
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                    };

                    // add roles to the list
                    var userRoles = await _userManager.GetRolesAsync(user);

                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    // generate the token with the claims using the jwtTokenService interface
                    var jwtToken = _jwtTokenService.GetToken(authClaims);

                    // return the generated jwt token
                    return new ServiceResponse<object>
                    {
                        HttpCode = HttpStatusCode.OK,
                        Data = new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                            expiration = jwtToken.ValidTo,
                            user = user.UserName
                        },
                        Message = "Logged in successful",
                        isSuccess = true
                    };
                }

            }
            return new ServiceResponse<object>
            {
                HttpCode = HttpStatusCode.BadRequest,
                Message = "Error logging in. Invalid token.",
                isSuccess = false
            };
        }

        public async Task<ServiceResponse<string>> GenerateForgotPasswordLink(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                return new ServiceResponse<string>
                {
                    HttpCode = HttpStatusCode.OK,
                    Data = token,
                    isSuccess = true
                };
            }

            return new ServiceResponse<string>
            {
                HttpCode = HttpStatusCode.BadRequest,
                Message = "User not found.",
                Data = null,
                isSuccess = false
            };
        }

        public async Task<ServiceResponse<object>> ResetPasswordAsync(ResetPassword model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user != null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                if (!resetPasswordResult.Succeeded)
                {
                    // storing errors if there are any
                    var errors = resetPasswordResult.Errors.Select(x => x.Description).ToList();

                    return new ServiceResponse<object>
                    {
                        HttpCode = HttpStatusCode.BadRequest,
                        Message = "Errors occured while trying to change password.",
                        Errors = errors,
                        isSuccess = false
                    };
                }

                // if password change is successful
                return new ServiceResponse<object>
                {
                    HttpCode = HttpStatusCode.OK,
                    Message = "Password successfully changed",
                    isSuccess = true
                };
            }
            return new ServiceResponse<object>
            {
                HttpCode = HttpStatusCode.BadRequest,
                Message = "Email not registered or incorrect.",
                isSuccess = false
            };
        }
    }
}
