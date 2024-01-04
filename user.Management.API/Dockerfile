#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["user.Management.API/user.Management.API.csproj", "user.Management.API/"]
RUN dotnet restore "user.Management.API/user.Management.API.csproj"
COPY . .
WORKDIR "/src/user.Management.API"
RUN dotnet build "user.Management.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "user.Management.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "user.Management.API.dll"]