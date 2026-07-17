FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY NuGetAnalyzer.csproj .
RUN dotnet restore --locked-mode=false
COPY Program.cs .
RUN dotnet publish -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/runtime:8.0
RUN useradd --create-home --uid 10001 analyzer
USER analyzer
WORKDIR /work
COPY --from=build /out /app
ENTRYPOINT ["dotnet", "/app/NuGetAnalyzer.dll"]
