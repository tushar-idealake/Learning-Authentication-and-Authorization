using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace user.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        [Authorize]
        [HttpGet("employees")]
        public IEnumerable<string> Get()
        {
            return new List<string> { "Tushar", "Ramesh", "Suresh" };
        }
    }
}
