const assert = require("assert");

const {
  normalizePhone,
  extractPhoneFromText,
  parseGuests,
  parseGuestsCsv,
  csvCell,
  sanitizeEventType
} = require("../utils");

assert.strictEqual(normalizePhone("+228 90 00-00-00"), "22890000000");

assert.deepStrictEqual(extractPhoneFromText("Marie +228 91 11 11 11"), {
  phone: "22891111111",
  strippedText: "Marie"
});

assert.deepStrictEqual(parseGuests("Marie|+228 91 11 11 11\nPaul +228 92 22 22 22"), [
  { fullName: "Marie", phone: "22891111111" },
  { fullName: "Paul", phone: "22892222222" }
]);

assert.deepStrictEqual(parseGuestsCsv("nom,numero\nAwa,22893333333"), [
  { fullName: "Awa", phone: "22893333333" }
]);

assert.strictEqual(csvCell('Invite "VIP"; table 1'), '"Invite ""VIP""; table 1"');
assert.strictEqual(sanitizeEventType("conference"), "conference");
assert.strictEqual(sanitizeEventType("inconnu"), "mariage");

console.log("utils tests ok");
