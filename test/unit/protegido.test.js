const request = require("supertest");   // 👈 IMPORTANTE
const app = require("../../server");    // ajusta la ruta según tu estructura

// puedes usar agent si necesitas mantener sesión en otros tests
const agent = request.agent(app);

describe("Rutas protegidas", () => {
  it("Debe redirigir a /login si no hay sesión", async () => {
    const res = await request(app).get("/creacionticket"); // 👈 simulamos acceso sin sesión
    expect(res.statusCode).toBe(302); // debe redirigir
    expect(res.header.location).toBe("/login");
  });
});
