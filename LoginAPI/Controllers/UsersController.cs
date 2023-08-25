using LoginAPI.Context;
using LoginAPI.Helpers;
using LoginAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace LoginAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private readonly AppDbContext _authContext; 
        public UsersController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username);

            if(user == null)
            {
                return NotFound(new { Message = "User not found" });
            }

            if(!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                return BadRequest(new {Message = "Password is incorect"});

            user.Token = CreateJwtToken(user);

            return Ok( new
                { 
                    Token = user.Token,
                    Message = "Login Success"
                });

        }

        [HttpPost("register")]

        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if( userObj == null)
            {
                return BadRequest();
            }

            //Check username
            if(await CheckUsernameExsistAsync(userObj.Username))
            {
                return BadRequest(new { Message = "Username already exists" });
            }

            //Check email
            if (await CheckEmailExsistAsync(userObj.Email))
            {
                return BadRequest(new { Message = "Email already exists" });
            }

            //Check password
            var pass = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString() });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new {Message = "User registered"});
        }


        private async Task<Boolean> CheckUsernameExsistAsync(string username)
        {
            return await _authContext.Users.AnyAsync(x => x.Username == username);
        }

        private async Task<Boolean> CheckEmailExsistAsync(string email)
        {
            return await _authContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();

            if (password.Length < 8)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password,"[0-9]")))
                sb.Append("Password should be alphanumeric"+Environment.NewLine);
            if (!(Regex.IsMatch(password, "[<,>,@,!,#,$,%,&,/,^,*,(,),_,+,\\[,\\],{,},?,.,:,|,',\\,,=,]")))
                sb.Append("Password must contain special character" + Environment.NewLine);
            
            return sb.ToString();
        }

        private string CreateJwtToken(User user)
        {
            var jwtHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("verysecretkey.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };

            var token = jwtHandler.CreateToken(tokenDescriptor);
            return jwtHandler.WriteToken(token);
        }

        
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
    }
}
