using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerAPI.Data;
using ServerAPI.Entities;
using ServerAPI.Entities.Response;
using ServerAPI.Helpers;
using ServerAPI.Models.Accounts;
using ServerAPI.Models.Response;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using ServerAPI.Models;
using System.Net;
using Microsoft.Net.Http.Headers;


namespace ServerAPI.Services
{
	public interface IAccountService
	{
		Task<AuthenticateResponse> Authenticate(AuthenticateRequest model);
		Task<AuthenticateResponse> RefreshToken(string token);
		public bool CheckLastJwtToken(string jwtToken, Account user);
		
		Task RevokeToken(string token);
		Task<ActionResult<AccountResponse>> UpdateUser([FromBody] UpdateRequest model, ClaimsPrincipal user);

	}

	public class AccountService : IAccountService
	{
		private readonly NorthwindContext _context;
		private readonly IMapper _mapper;
		private readonly IConfiguration _configuration;
		private readonly AppSettings _appSettings;
		private readonly UserManager<Account> userManager;
		private readonly RoleManager<IdentityRole> roleManager;

		public AccountService(
			NorthwindContext context,
			IMapper mapper,
			IOptions<AppSettings> appSettings,
			IConfiguration configuration,
			UserManager<Account> _userManager,
			RoleManager<IdentityRole> _roleManager)
		{
			_context = context;
			_mapper = mapper;
			_configuration = configuration;
			_appSettings = appSettings.Value;
			userManager = _userManager;
			roleManager = _roleManager;
		}

		public async Task<AuthenticateResponse> Authenticate(AuthenticateRequest model)
		{
			var user = await userManager.FindByNameAsync(model.UserName);			
			if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
			{
				// authentication successful so generate jwt and refresh tokens
				var jwtToken = await GenerateJWTToken(user);
				var refreshToken = GenerateRefreshToken();
				// save refresh token
				user.RefreshTokens.Add(refreshToken);
				user.JwtToken = jwtToken;
				var result = await userManager.UpdateAsync(user);
				if (!result.Succeeded)
				{
					throw new AppException("Something went wrong while adding token to user.");
				}

				var response = _mapper.Map<AuthenticateResponse>(user);
				response.JwtToken = jwtToken;
				response.RefreshToken = refreshToken.Token;
				response.Expires = refreshToken.Expires;
				return response;
			}
			throw new AppException("User not found");
		}

		public async Task<ActionResult<AccountResponse>> UpdateUser([FromBody] UpdateRequest model, ClaimsPrincipal user)
		{
			var userToUpdate = await userManager.FindByNameAsync(model.UserName);
			if (userToUpdate == null)
			{
				return new NotFoundResult();
			}

			if (user.Identity.Name != userToUpdate.UserName && user.Claims.Where(s => s.Type == model.Role).Any(s => s.Value == "Admin") == false)
			{
				return new UnauthorizedResult();
			}
			var mappedUser = _mapper.Map(model, userToUpdate);
			var result = await userManager.UpdateAsync(mappedUser);
			if (!result.Succeeded)
			{
				return new BadRequestResult();
			}
			mappedUser.Updated = DateTime.Now;
			var mappedResult = _mapper.Map<AccountResponse>(mappedUser);
			return mappedResult;
		}
		#region Tokens

		public async Task<AuthenticateResponse> RefreshToken(string token)
		{
			var (refreshToken, account) = GetRefreshToken(token);

			// replace old refresh token with a new one and save
			var newRefreshToken = GenerateRefreshToken();
			refreshToken.Revoked = DateTime.UtcNow;
			refreshToken.ReplacedByToken = newRefreshToken.Token;
			account.RefreshTokens.Add(newRefreshToken);
			var result = await userManager.UpdateAsync(account);
			if (!result.Succeeded)
			{
				throw new AppException("Refreshtoken could not be added!");
			}
			// generate new jwt
			var jwtToken = await GenerateJWTToken(account);
			var response = _mapper.Map<AuthenticateResponse>(account);
			response.JwtToken = jwtToken;
			response.RefreshToken = newRefreshToken.Token;
			return response;
		}

		public async Task RevokeToken(string token)
		{
			var (refreshToken, account) = GetRefreshToken(token);

			// revoke token and save
			refreshToken.Revoked = DateTime.UtcNow;

			var result = await userManager.UpdateAsync(account);
			if (!result.Succeeded)
				throw new AppException("Tokenrevoke failed!");
		}

		private async Task<string> GenerateJWTToken(Account account)
		{
			var userRoles = await userManager.GetRolesAsync(account);
			Employees employee = _context.Employees.Where(x => x.EmployeeId == account.EmployeeId).FirstOrDefault();
			var authClaims = new List<Claim>
				{
					new Claim(ClaimTypes.Name, account.UserName),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
					new Claim(ClaimTypes.Country, employee.Country)
				};

			foreach (var userRole in userRoles)
			{
				authClaims.Add(new Claim(ClaimTypes.Role, userRole));
			}
						
			var key = Encoding.ASCII.GetBytes(_configuration["JWT:Secret"]);
			var tokenDescriptor = new JwtSecurityToken(
				issuer: _configuration["JWT:ValidIssuer"],
				audience: _configuration["JWT:ValidAudience"],
				expires: DateTime.UtcNow.AddMinutes(10),
				claims: authClaims,
				signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
				
			);
			
			var token = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
			return token;
		}

		private (RefreshToken, Account) GetRefreshToken(string token)
		{
			var account = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
			if (account == null) throw new AppException("Invalid token");
			var refreshToken = account.RefreshTokens.Single(x => x.Token == token);
			if (!refreshToken.IsActive) throw new AppException("Invalid token");
			return (refreshToken, account);
		}
		private RefreshToken GenerateRefreshToken()
		{
			return new RefreshToken
			{
				Token = RandomTokenString(),
				Expires = DateTime.UtcNow.AddDays(7),
				Created = DateTime.UtcNow,
			};
		}

		private string RandomTokenString()
		{
			using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
			var randomBytes = new byte[40];
			rngCryptoServiceProvider.GetBytes(randomBytes);
			return BitConverter.ToString(randomBytes).Replace("-", "");
		}

		public  bool CheckLastJwtToken(string jwtToken, Account user)
		{
			var userRefreshtoken = user.RefreshTokens.OrderByDescending(x => x.Id).FirstOrDefault().ToString();
			
			bool refreshTokenCheck = CheckLastRefreshToken(userRefreshtoken, user);
			if (jwtToken != "Bearer " + user.JwtToken || refreshTokenCheck != true )
			{
				return false;
			}
			else return true;			
		}
		public bool CheckLastRefreshToken(string refreshToken, Account user)
		{			
			var userInDb = _context.Users.Where(x => x.EmployeeId == user.EmployeeId).FirstOrDefault();
			var lastRefreshToken = userInDb.RefreshTokens.OrderByDescending(x => x.Id).FirstOrDefault().ToString();			

			if (refreshToken != lastRefreshToken)
			{
				return false;
			}
			else return true;
		}
		
		#endregion
	}
}

