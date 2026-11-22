/**
 * Who did something, in words. The backend records the signed-in user's name, or "system" when no
 * one was signed in (login off, or a background job: CurrentActor.SYSTEM). Captures uploaded
 * before uploads recorded anyone have no uploader at all. Each case says so, rather than leaving
 * the line blank and looking like a missing feature.
 */
export const SYSTEM_ACTOR = 'system';

/** "by alice", or "without sign-in" for the system actor. */
export function actorWords(actor: string | null | undefined): string {
  if (!actor) return 'by someone not recorded';
  return actor === SYSTEM_ACTOR ? 'without sign-in' : `by ${actor}`;
}

/** A capture's uploader: "by alice", "uploaded without sign-in", or "uploader not recorded". */
export function uploaderWords(uploadedBy: string | null | undefined): string {
  if (!uploadedBy) return 'uploader not recorded';
  return uploadedBy === SYSTEM_ACTOR ? 'uploaded without sign-in' : `by ${uploadedBy}`;
}
