using System.ComponentModel.DataAnnotations;

namespace ServerAPI.Models.Response
{
    public class AuthenticateRequest
    {
        [Required]
        
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }
    }
}