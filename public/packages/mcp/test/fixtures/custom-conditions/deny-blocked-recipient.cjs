module.exports = ({ registerCustomCondition }) => {
  registerCustomCondition('denyBlockedRecipient', {
    validate(config) {
      if (!config || typeof config !== 'object') {
        throw new Error('config must be an object');
      }
      if (
        typeof config.blockedDomain !== 'string' ||
        config.blockedDomain.length === 0
      ) {
        throw new Error('blockedDomain must be a non-empty string');
      }
    },
    enforce(config, ctx) {
      const blockedDomain = String(config.blockedDomain).toLowerCase();
      const recipients = Array.isArray(ctx.recipients) ? ctx.recipients : [];
      const hasBlockedRecipient = recipients.some((value) =>
        String(value).trim().toLowerCase().endsWith(`@${blockedDomain}`),
      );
      return hasBlockedRecipient
        ? {
          allow: false,
          reason: `recipient matches blocked domain '${blockedDomain}'`,
        }
        : { allow: true };
    },
  });
};
