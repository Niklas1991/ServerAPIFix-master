using AutoMapper;
using ServerAPI;
using ServerAPI.Entities;
using ServerAPI.Models;
using ServerAPI.Models.Response;
using System.Collections.Generic;

namespace ServerAPI.Data
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
           CreateMap<RegisterRequest, Account>().ReverseMap();
           CreateMap<AuthenticateResponse, Account>().ReverseMap();
           CreateMap<UpdateRequest, AccountResponse>().ReverseMap();
           CreateMap<UpdateRequest, Account>().ReverseMap();
           CreateMap<AccountResponse, Account>().ReverseMap();
           CreateMap<Account, UserResponse>().ReverseMap();
           CreateMap<AccountResponse, RegisterRequest>().ReverseMap();
            CreateMap<OrderResponse, Orders>().ReverseMap();
        }

    }
}
