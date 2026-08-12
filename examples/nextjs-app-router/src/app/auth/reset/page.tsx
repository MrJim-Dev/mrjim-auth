import { Suspense } from "react";
import { ResetPasswordForm } from "../../../components/ResetPasswordForm";

export default function ResetPage() {
  return (
    <Suspense fallback={<section className="card"><p>Loading reset form…</p></section>}>
      <ResetPasswordForm />
    </Suspense>
  );
}
