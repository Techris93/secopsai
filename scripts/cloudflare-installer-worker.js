export default {
  async fetch(request) {
    const url = new URL(request.url);

    const targets = {
      "/install.sh": "https://docs.secopsai.dev/install.sh",
      "/setup.sh": "https://docs.secopsai.dev/setup.sh",
    };

    const target = targets[url.pathname];

    if (!target) {
      return new Response("Not found", { status: 404 });
    }

    // Proxy script content so users can always fetch from secopsai.dev
    // even when docs are hosted on docs.secopsai.dev.
    const upstream = await fetch(target, {
      method: "GET",
      headers: {
        "User-Agent": "secopsai-installer-worker",
      },
    });

    if (!upstream.ok) {
      return new Response("Upstream installer unavailable", { status: 502 });
    }

    const body = await upstream.text();

    return new Response(body, {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "public, max-age=300",
      },
    });
  },
};
