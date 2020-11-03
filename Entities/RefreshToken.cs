using Microsoft.EntityFrameworkCore;
using ServerAPI.Entities;
using System;
using System.ComponentModel.DataAnnotations;

namespace ServerAPI.Entities.Response
{
    [Owned]
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public Account Account { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public DateTime Created { get; set; }
		
		public DateTime? Revoked { get; set; }
		
		public string ReplacedByToken { get; set; }
        public bool IsActive => Revoked == null && !IsExpired;
    }
}