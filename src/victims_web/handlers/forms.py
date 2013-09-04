
from wtforms import Form, fields, validators

from victims_web.config import SUBMISSION_GROUPS


class RequiredIf(validators.Required):

    def __init__(self, other_fieldname, value, negate, *args, **kwargs):
        self.other_fieldname = other_fieldname
        self.negate = negate
        self.value = value
        super(RequiredIf, self).__init__(*args, **kwargs)

    def test_other_field(self, form):
        other_field = form._fields.get(self.other_fieldname)
        if other_field is None:
            raise Exception('Invalid field "%s"' % self.other_fieldname)
        test = self.value == other_field.data
        test = not test if self.negate else test
        return test

    def __call__(self, form, field):
        if self.test_other_field(form):
            super(RequiredIf, self).__call__(form, field)


class ValidateOnlyIf(RequiredIf):

    def __init__(self, validators, *args, **kwargs):
        self.validators = validators
        super(ValidateOnlyIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        if self.test_other_field(form):
            for validator in self.validators:
                validator.__call__(form, field)


class GroupSelectField(fields.SelectField):
    DEFAULT_GROUP = '---'
    VALID_GROUPS = SUBMISSION_GROUPS.keys()

    def __init__(self, validators, *args, **kwargs):
        super(GroupSelectField, self).__init__('Group', *args, **kwargs)
        self.choices = [(self.DEFAULT_GROUP, 'unset')]
        for group in self.VALID_GROUPS:
            self.choices.append((group, group))
        self.validators = validators


class ArchiveSubmit(Form):
    cves = fields.StringField('CVE(s)', validators=[
        RequiredIf('group', GroupSelectField.DEFAULT_GROUP, True)
    ])
    archive = fields.FileField('Archive', validators=[
        #validators.FileAllowed(ALLOWED_EXTENSIONS),
    ])
    group = GroupSelectField()
    for (g, fs) in SUBMISSION_GROUPS.items():
        if len(fs) > 0:
            for f in fs:
                exec('%s_%s' % (g, f) + ' = fields.HiddenField(f)')
