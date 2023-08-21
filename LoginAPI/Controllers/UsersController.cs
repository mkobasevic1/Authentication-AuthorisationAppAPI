﻿using LoginAPI.Context;
using LoginAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

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

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username && x.Password==userObj.Password);

            if(user == null)
            {
                return NotFound(new { Message = "User not found" });
            }

            return Ok( new
                { Message = "Login Success"});

        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if( userObj == null)
            {
                return BadRequest();
            }

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new {Message = "User registered"});
        }
    }
}
