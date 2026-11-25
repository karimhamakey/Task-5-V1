import Joi from 'joi';
import { Instructor } from '../models/Instructor.js';

// Fields that are safe to send to the client.
// password, apiKey, privateEmail and privatePhone are never sent.
const PUBLIC_FIELDS = 'name username department role';

function publicProfile(doc) {
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role
  };
}

// Joi options:
//  - abortEarly: false -> report EVERY problem, not just the first one
//  - wrap.label: false -> "password is required" instead of "\"password\" is required"
const JOI_OPTIONS = { abortEarly: false, errors: { wrap: { label: false } } };

// Turns Joi's error into one readable sentence, e.g.
// "username must be a string, password is required"
function joiMessage(error) {
  return error.details.map((d) => d.message).join(', ');
}

// Joi: both fields MUST be plain strings. An object like {"$ne": null} fails here.
const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(50).required(),
  password: Joi.string().min(1).max(128).required()
}).messages({
  'any.required': '{#label} is required',
  'string.base': '{#label} must be a string',
  'string.empty': '{#label} cannot be empty',
  'string.max': '{#label} must be at most {#limit} characters',
  'object.unknown': '{#label} is not allowed'
});

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { value, error } = loginSchema.validate(req.body, JOI_OPTIONS);
    if (error) return res.status(400).json({ message: joiMessage(error) });

    // Query by username only. The password is compared in code with bcrypt,
    // never inside the database query.
    const instructor = await Instructor.findOne({ username: value.username }).select('+password');

    // NOTE: these two 401s stay identical ON PURPOSE. Saying "user not found"
    // vs "wrong password" would let an attacker discover which usernames exist.
    if (!instructor) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await instructor.comparePassword(value.password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}

// GET /api/instructors  (public directory)
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}

// Only `name` (a string) is used. Unknown keys (role, username, $where, ...)
// are stripped and ignored, so they can never reach the database.
const searchSchema = Joi.object({
  name: Joi.string().trim().min(1).max(50)
})
  .options({ stripUnknown: true })
  .messages({
    'string.base': '{#label} must be a string',
    'string.empty': '{#label} cannot be empty',
    'string.max': '{#label} must be at most {#limit} characters'
  });

// Escape regex special characters so the user's text is matched literally.
function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// GET /api/instructors/search?name=Smith
export async function searchInstructors(req, res, next) {
  try {
    const { value, error } = searchSchema.validate(req.query, JOI_OPTIONS);
    if (error) return res.status(400).json({ message: joiMessage(error) });

    // No usable search term -> nothing to search for.
    if (!value.name) return res.json({ count: 0, instructors: [] });

    // The server builds the filter itself; the client only supplies text.
    const filter = { name: new RegExp(escapeRegex(value.name), 'i') };
    const instructors = await Instructor.find(filter)
      .select(PUBLIC_FIELDS)
      .sort({ name: 1 })
      .lean();
    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}