(async () => {
  const root = document.querySelector("[data-comments]");
  if (!root) return;

  const slug = root.dataset.slug;
  const list = root.querySelector("[data-comment-list]");
  const form = root.querySelector("[data-comment-form]");
  const status = root.querySelector("[data-comment-status]");

  const renderComment = (comment) => {
    const item = document.createElement("article");
    item.className = "comment";
    const name = document.createElement("strong");
    name.textContent = comment.name || "Anonymous";
    const date = document.createElement("p");
    date.className = "meta";
    date.textContent = comment.created_at ? new Date(comment.created_at).toLocaleString() : "Pending date";
    const body = document.createElement("p");
    body.textContent = comment.body || "";
    item.append(name, date, body);
    return item;
  };

  const loadComments = async () => {
    if (!list) return;
    list.textContent = "Loading comments...";
    try {
      const response = await fetch(`/api/comments?slug=${encodeURIComponent(slug)}`);
      const payload = await response.json();
      list.textContent = "";
      const comments = payload.comments || [];
      if (!comments.length) {
        list.textContent = "No approved comments yet.";
        return;
      }
      comments.forEach((comment) => list.appendChild(renderComment(comment)));
    } catch {
      list.textContent = "Comments are temporarily unavailable.";
    }
  };

  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    status.textContent = "Submitting...";
    const data = new FormData(form);
    const body = Object.fromEntries(data.entries());
    body.slug = slug;
    try {
      const response = await fetch("/api/comments", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "comment rejected");
      form.reset();
      status.textContent = "Thanks. Your comment is queued for moderation.";
    } catch (error) {
      status.textContent = `Could not submit comment: ${error.message}`;
    }
  });

  await loadComments();
})();
