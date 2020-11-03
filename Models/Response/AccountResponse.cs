using System;

namespace ServerAPI.Models.Response
{
    public class AccountResponse
    {
       public string UserName { get; set; }
        public string Email { get; set; }
        public DateTime Created { get; set; }
        public DateTime? Updated { get; set; }
        
    }
}