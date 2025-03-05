function apiTest(path) {
    describe(`Get ${path}`, () => {
        it("localhost should return status 200", async() => {
            const response = await fetch(`http://localhost:3333${path}`, {});
            expect(response.status).toBe(200);
        });
    });
}

