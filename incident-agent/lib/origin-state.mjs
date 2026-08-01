export function originRestarted(origin, previous) {
  if (!previous) return false;
  return origin.restartCount > previous.restartCount
    || Boolean(origin.generation && previous.generation && origin.generation !== previous.generation);
}
