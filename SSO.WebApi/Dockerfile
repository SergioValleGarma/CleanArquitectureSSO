FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copiar csproj para aprovechar cache
COPY SSO.WebApi/SSO.WebApi.csproj SSO.WebApi/
COPY SSO.Application/SSO.Application.csproj SSO.Application/
COPY SSO.Infrastructure/SSO.Infrastructure.csproj SSO.Infrastructure/
COPY SSO.Domain/SSO.Domain.csproj SSO.Domain/

RUN dotnet restore "SSO.WebApi/SSO.WebApi.csproj"

# Copiar todo el código
COPY . .

WORKDIR /src/SSO.WebApi
RUN dotnet build "SSO.WebApi.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "SSO.WebApi.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "SSO.WebApi.dll"]
