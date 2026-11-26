import stylesheet from "../../../styles/site.css?inline";

export function GET() {
  return new Response(stylesheet, {
    headers: { "Content-Type": "text/css; charset=utf-8" },
  });
}
